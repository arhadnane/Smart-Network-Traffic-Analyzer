using System.Text;
using System.Text.Json;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

public sealed class OllamaAnalysisService : IOllamaAnalysisService
{
    private readonly HttpClient _httpClient;
    private readonly string _ollamaUrl = "http://localhost:11434";
    private readonly string _model = "phi3:mini"; // Modèle léger et rapide

    public OllamaAnalysisService(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _httpClient.Timeout = TimeSpan.FromMinutes(2); // Augmenté à 2 minutes pour les modèles lents
    }

    public async Task<string> AnalyzeConnectionAsync(string remoteIp, string processName, string hostname, string country, CancellationToken ct = default)
    {
        try
        {
            Console.WriteLine($"[Ollama] Début analyse pour {remoteIp} ({processName})");
            var prompt = CreateAnalysisPrompt(remoteIp, processName, hostname, country);
            var response = await CallOllamaAsync(prompt, ct);
            Console.WriteLine($"[Ollama] Analyse terminée pour {remoteIp}");
            return response;
        }
        catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
        {
            Console.WriteLine($"[Ollama] Timeout pour {remoteIp}");
            return "⏱️ Timeout Ollama: L'analyse prend trop de temps. Essayez un modèle plus rapide (llama3.2:1b).";
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"[Ollama] Erreur HTTP: {ex.Message}");
            return "🔌 Ollama non disponible: Vérifiez qu'Ollama est démarré (localhost:11434).";
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Ollama] Erreur générale: {ex.Message}");
            return $"❌ Erreur d'analyse: {ex.Message}";
        }
    }

    private string CreateAnalysisPrompt(string remoteIp, string processName, string hostname, string country)
    {
        return $@"Analyse rapide en français (max 200 mots):

IP: {remoteIp} | Process: {processName} | Host: {hostname ?? "?"} | Pays: {country ?? "?"}

Fournis:
1. Type de service (Google, CDN, etc.)
2. Risque: Faible/Moyen/Élevé
3. Recommandation (1 phrase)

Sois concis et direct.";
    }

    private async Task<string> CallOllamaAsync(string prompt, CancellationToken ct)
    {
        var request = new
        {
            model = _model,
            prompt = prompt,
            stream = false,
            options = new
            {
                temperature = 0.1, // Plus déterministe
                num_predict = 200, // Limité à 200 tokens
                top_k = 10,        // Réduit l'espace de recherche
                top_p = 0.5,       // Plus focalisé
                num_ctx = 1024     // Contexte réduit pour être plus rapide
            }
        };

        var json = JsonSerializer.Serialize(request);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await _httpClient.PostAsync($"{_ollamaUrl}/api/generate", content, ct);
        
        if (!response.IsSuccessStatusCode)
        {
            return "❌ Ollama service non disponible. Vérifiez que Ollama est démarré avec le modèle phi3:mini.";
        }

        var responseText = await response.Content.ReadAsStringAsync(ct);
        var jsonResponse = JsonSerializer.Deserialize<JsonElement>(responseText);
        
        if (jsonResponse.TryGetProperty("response", out var responseProperty))
        {
            return responseProperty.GetString() ?? "Réponse vide d'Ollama";
        }

        return "❌ Format de réponse Ollama invalide";
    }

    public async Task<bool> CheckOllamaAvailabilityAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync($"{_ollamaUrl}/api/tags");
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }
}
