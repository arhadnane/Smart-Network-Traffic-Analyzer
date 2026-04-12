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
    private readonly HttpClient _httpClient;
    private readonly ILoggingService _logger;
    private readonly string _ollamaUrl;
    private readonly string _model;

    public OllamaAnalysisService(HttpClient httpClient, ILoggingService logger, string ollamaUrl = "http://localhost:11434", string model = "phi3:mini")
    {
        _httpClient = httpClient;
        _httpClient.Timeout = TimeSpan.FromMinutes(2);
        _logger = logger;
        _ollamaUrl = ollamaUrl;
        _model = model;
    }

    public async Task<string> AnalyzeConnectionAsync(string remoteIp, string processName, string hostname, string country, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(remoteIp);

        try
        {
            _logger.Info($"Ollama analysis starting for {remoteIp} ({processName})");
            var prompt = CreateAnalysisPrompt(remoteIp, processName, hostname, country);
            var response = await CallOllamaAsync(prompt, ct);
            _logger.Info($"Ollama analysis completed for {remoteIp}");
            return response;
        }
        catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
        {
            _logger.Warn($"Ollama timeout for {remoteIp}");
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

    private static string CreateAnalysisPrompt(string remoteIp, string processName, string hostname, string country)
    {
        return $"""Analyse rapide en français (max 200 mots):

IP: {remoteIp} | Process: {processName} | Host: {hostname ?? "N/A"} | Pays: {country ?? "N/A"}

Fournis:
1. Type de service (Google, CDN, etc.)
2. Risque: Faible/Moyen/Élevé
3. Recommandation (1 phrase)

Sois concis et direct.""";
    }

    private async Task<string> CallOllamaAsync(string prompt, CancellationToken ct)
    {
        var request = new
        {
            model = _model,
            prompt,
            stream = false,
            options = new
            {
                temperature = 0.1,
                num_predict = 200,
                top_k = 10,
                top_p = 0.5,
                num_ctx = 1024
            }
        };

        var json = JsonSerializer.Serialize(request);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await _httpClient.PostAsync($"{_ollamaUrl}/api/generate", content, ct);

        if (!response.IsSuccessStatusCode)
        {
            return $"❌ Ollama service non disponible (HTTP {(int)response.StatusCode}). Vérifiez que Ollama est démarré avec le modèle {_model}.";
        }

        var responseText = await response.Content.ReadAsStringAsync(ct);
        var jsonResponse = JsonSerializer.Deserialize<JsonElement>(responseText);

        if (jsonResponse.TryGetProperty("response", out var responseProperty))
        {
            return responseProperty.GetString() ?? "Réponse vide d'Ollama";
        }

        return "❌ Format de réponse Ollama invalide";
    }
}