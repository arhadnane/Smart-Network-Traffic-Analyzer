using System.Text;
using System.Text.Json;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Connects to a local Ollama instance for AI-powered connection analysis.
/// </summary>
public sealed class OllamaAnalysisService : IOllamaAnalysisService
{
    public const string DefaultModel = "glm-5.1:cloud";

    private static readonly string[] FallbackModels =
    {
        DefaultModel,
        "llama3.2:3b",
        "llama3.2:1b",
        "mistral:7b",
        "qwen2.5:7b"
    };

    private readonly HttpClient _httpClient;
    private readonly ILoggingService _logger;
    private readonly ISettingsService _settings;
    private readonly string _ollamaUrl;
    private string _selectedModel;

    public OllamaAnalysisService(HttpClient httpClient, ILoggingService logger, ISettingsService settings, string ollamaUrl = "http://localhost:11434", string model = DefaultModel)
    {
        _httpClient = httpClient;
        _httpClient.Timeout = TimeSpan.FromMinutes(2);
        _logger = logger;
        _settings = settings;
        _ollamaUrl = ollamaUrl;
        _selectedModel = settings.Get("ollama.model", model);
    }

    public string SelectedModel => _selectedModel;

    public async Task<string> AnalyzeConnectionAsync(ConnectionAnalysisContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(context.RemoteIp);

        try
        {
            var model = SelectedModel;
            _logger.Info($"Ollama analysis starting for {context.RemoteIp} ({context.ProcessName}) with model {model}");
            var prompt = CreateAnalysisPrompt(context);
            var response = await CallOllamaAsync(prompt, model, ct);
            _logger.Info($"Ollama analysis completed for {context.RemoteIp} with model {model}");
            return response;
        }
        catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
        {
            _logger.Warn($"Ollama timeout for {context.RemoteIp}");
            return "⏱️ Timeout Ollama: L'analyse prend trop de temps. Essayez un modèle plus rapide (llama3.2:1b).";
        }
        catch (HttpRequestException ex)
        {
            _logger.Warn($"Ollama HTTP error: {ex.Message}");
            return "🔌 Ollama non disponible: Vérifiez qu'Ollama est démarré (localhost:11434).";
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.Error($"Ollama general error: {ex.Message}", ex);
            return $"❌ Erreur d'analyse: {ex.Message}";
        }
    }

    public async Task<bool> CheckAvailabilityAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync($"{_ollamaUrl}/api/tags", CancellationToken.None);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public async Task<IReadOnlyList<string>> GetAvailableModelsAsync(CancellationToken ct = default)
    {
        try
        {
            var response = await _httpClient.GetAsync($"{_ollamaUrl}/api/tags", ct);
            if (!response.IsSuccessStatusCode)
            {
                return FallbackModels;
            }

            var responseText = await response.Content.ReadAsStringAsync(ct);
            var json = JsonSerializer.Deserialize<JsonElement>(responseText);

            if (!json.TryGetProperty("models", out var modelsElement) || modelsElement.ValueKind != JsonValueKind.Array)
            {
                return FallbackModels;
            }

            var models = modelsElement
                .EnumerateArray()
                .Select(static modelElement => modelElement.TryGetProperty("name", out var nameElement)
                    ? nameElement.GetString()
                    : null)
                .Where(static name => !string.IsNullOrWhiteSpace(name))
                .Select(static name => name!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            return models.Length == 0 ? FallbackModels : models;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.Warn($"Unable to retrieve Ollama models: {ex.Message}");
            return FallbackModels;
        }
    }

    public void SetSelectedModel(string model)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(model);
        _selectedModel = model.Trim();
        _settings.Set("ollama.model", _selectedModel);
    }

    private string CreateAnalysisPrompt(ConnectionAnalysisContext ctx)
    {
        var lang = _settings.Get("app.language", "en");
        return lang == "fr" ? CreateFrenchPrompt(ctx) : CreateEnglishPrompt(ctx);
    }

    private static string CreateFrenchPrompt(ConnectionAnalysisContext ctx)
    {
        return $"""
            Tu es un expert en cybersécurité et en analyse de processus Windows.
            Analyse cette connexion réseau de manière approfondie et révèle tout ce qu'il faut savoir.
            Réponds en français.

            === DONNÉES DE LA CONNEXION ===
            Process: {ctx.ProcessName} (PID: {ctx.ProcessId})
            Chemin: {ctx.ProcessPath ?? "Non disponible"}
            Description: {ctx.ProcessDescription ?? "Non disponible"}
            Éditeur: {ctx.ProcessCompany ?? "Non disponible"}
            Fenêtre active: {ctx.ProcessWindowTitle ?? "Aucune / arrière-plan"}
            IP distante: {ctx.RemoteIp}
            Port distant: {ctx.RemotePort}
            Hostname: {ctx.Hostname ?? "Non résolu"}
            Pays: {ctx.Country ?? "Inconnu"}
            Direction: {ctx.Direction}
            Données reçues: {FormatBytes(ctx.BytesIn)}
            Données envoyées: {FormatBytes(ctx.BytesOut)}

            === ANALYSE DEMANDÉE ===

            📌 1. IDENTITÉ DU PROCESS
            - Quel est ce processus ? Éditeur, rôle exact dans Windows/application.
            - Est-il légitime ? Signé par Microsoft ou un éditeur connu ?
            - Peut-il être usurpé par un malware (processus homonyme) ?

            🔍 2. SECRETS ET COMPORTEMENT CACHÉ
            - Ce processus collecte-t-il des données (télémétrie, diagnostics, keylogging) ?
            - Envoie-t-il des données à des serveurs distants ? Lesquels et pourquoi ?
            - Y a-t-il des comportements cachés connus (phoning home, tracking) ?

            🌐 3. ANALYSE DE CETTE CONNEXION
            - Pourquoi ce processus contacte-t-il cette IP/ce hostname ?
            - Le volume de données ({FormatBytes(ctx.BytesOut)} envoyé, {FormatBytes(ctx.BytesIn)} reçu) est-il normal ?
            - Le port {ctx.RemotePort} est-il habituel pour ce processus ?

            🛡️ 4. ÉVALUATION SÉCURITÉ
            - Niveau de risque: 🟢 Faible / 🟡 Moyen / 🟠 Élevé / 🔴 Critique
            - Vulnérabilités connues liées à ce processus
            - Ce processus peut-il être exploité comme vecteur d'attaque ?

            🔒 5. RECOMMANDATIONS
            - Faut-il bloquer cette connexion ?
            - Comment durcir/restreindre ce processus ?
            - Règles firewall suggérées si nécessaire

            Sois précis, technique et transparent. Ne cache rien.
            """;
    }

    private static string CreateEnglishPrompt(ConnectionAnalysisContext ctx)
    {
        return $"""
            You are a cybersecurity expert and Windows process analyst.
            Deeply analyze this network connection and reveal everything there is to know.
            Respond in English.

            === CONNECTION DATA ===
            Process: {ctx.ProcessName} (PID: {ctx.ProcessId})
            Path: {ctx.ProcessPath ?? "Unavailable"}
            Description: {ctx.ProcessDescription ?? "Unavailable"}
            Publisher: {ctx.ProcessCompany ?? "Unavailable"}
            Active window: {ctx.ProcessWindowTitle ?? "None / background"}
            Remote IP: {ctx.RemoteIp}
            Remote Port: {ctx.RemotePort}
            Hostname: {ctx.Hostname ?? "Unresolved"}
            Country: {ctx.Country ?? "Unknown"}
            Direction: {ctx.Direction}
            Data received: {FormatBytes(ctx.BytesIn)}
            Data sent: {FormatBytes(ctx.BytesOut)}

            === ANALYSIS REQUESTED ===

            📌 1. PROCESS IDENTITY
            - What is this process? Publisher, exact role in Windows/application.
            - Is it legitimate? Signed by Microsoft or a known publisher?
            - Can it be spoofed by malware (homonymous process)?

            🔍 2. SECRETS & HIDDEN BEHAVIOR
            - Does this process collect data (telemetry, diagnostics, keylogging)?
            - Does it send data to remote servers? Which ones and why?
            - Are there known hidden behaviors (phoning home, tracking)?

            🌐 3. CONNECTION ANALYSIS
            - Why is this process contacting this IP/hostname?
            - Is the data volume ({FormatBytes(ctx.BytesOut)} sent, {FormatBytes(ctx.BytesIn)} received) normal?
            - Is port {ctx.RemotePort} typical for this process?

            🛡️ 4. SECURITY ASSESSMENT
            - Risk level: 🟢 Low / 🟡 Medium / 🟠 High / 🔴 Critical
            - Known vulnerabilities related to this process
            - Can this process be exploited as an attack vector?

            🔒 5. RECOMMENDATIONS
            - Should this connection be blocked?
            - How to harden/restrict this process?
            - Suggested firewall rules if necessary

            Be precise, technical, and transparent. Hide nothing.
            """;
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes == 0) return "0 B";
        string[] sizes = { "B", "KB", "MB", "GB" };
        int order = 0;
        double size = bytes;
        while (size >= 1024 && order < sizes.Length - 1) { order++; size /= 1024; }
        return $"{size:0.##} {sizes[order]}";
    }

    private async Task<string> CallOllamaAsync(string prompt, string model, CancellationToken ct)
    {
        var request = new
        {
            model,
            prompt,
            think = false,
            stream = false,
            options = new
            {
                temperature = 0.3,
                num_predict = 1500,
                top_k = 40,
                top_p = 0.8,
                num_ctx = 4096
            }
        };

        var json = JsonSerializer.Serialize(request);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await _httpClient.PostAsync($"{_ollamaUrl}/api/generate", content, ct);

        if (!response.IsSuccessStatusCode)
        {
            return $"❌ Ollama service non disponible (HTTP {(int)response.StatusCode}). Vérifiez que Ollama est démarré avec le modèle {model}.";
        }

        var responseText = await response.Content.ReadAsStringAsync(ct);
        var jsonResponse = JsonSerializer.Deserialize<JsonElement>(responseText);

        if (jsonResponse.TryGetProperty("error", out var errorProperty))
        {
            var error = errorProperty.GetString();
            if (!string.IsNullOrWhiteSpace(error))
            {
                return $"❌ Ollama a retourné une erreur: {error}";
            }
        }

        if (jsonResponse.TryGetProperty("response", out var responseProperty))
        {
            var text = responseProperty.GetString();
            if (!string.IsNullOrWhiteSpace(text))
            {
                return text;
            }

            if (jsonResponse.TryGetProperty("thinking", out var thinkingProperty))
            {
                var thinking = thinkingProperty.GetString();
                if (!string.IsNullOrWhiteSpace(thinking))
                {
                    return $"⚠️ Le modèle a renvoyé un raisonnement sans réponse finale. Résumé du raisonnement:\n{thinking}";
                }
            }

            return "⚠️ Ollama a répondu sans contenu. Essayez un autre modèle ou relancez l'analyse.";
        }

        return "❌ Format de réponse Ollama invalide";
    }
}