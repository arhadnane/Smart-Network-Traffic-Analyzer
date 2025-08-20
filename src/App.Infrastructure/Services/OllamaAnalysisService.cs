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
        _httpClient.Timeout = TimeSpan.FromSeconds(30);
    }

    public async Task<string> AnalyzeConnectionAsync(string remoteIp, string processName, string hostname, string country, CancellationToken ct = default)
    {
        try
        {
            var prompt = CreateAnalysisPrompt(remoteIp, processName, hostname, country);
            var response = await CallOllamaAsync(prompt, ct);
            return response;
        }
        catch (Exception ex)
        {
            return $"❌ Erreur d'analyse Ollama: {ex.Message}";
        }
    }

    private string CreateAnalysisPrompt(string remoteIp, string processName, string hostname, string country)
    {
        return $@"Analyse cette connexion réseau et fournis une analyse détaillée en français :

📡 **Connexion Réseau**
• IP: {remoteIp}
• Processus: {processName}
• Hostname: {hostname ?? "Non résolu"}
• Pays: {country ?? "Non déterminé"}

Fournis une analyse structurée avec :
1. **Résumé** : Description simple de cette connexion
2. **Évaluation sécurité** : Niveau de risque (Faible/Moyen/Élevé) et pourquoi
3. **Analyse processus** : Ce que fait ce processus typiquement
4. **Recommandations** : Actions recommandées si nécessaire

Réponds en français, sois concis mais informatif (max 300 mots).";
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
                temperature = 0.3,
                num_predict = 300
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
