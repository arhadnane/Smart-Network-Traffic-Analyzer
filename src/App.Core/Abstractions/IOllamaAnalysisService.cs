namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Connects to a local Ollama instance for AI-powered connection analysis.
/// </summary>
public interface IOllamaAnalysisService
{
    Task<string> AnalyzeConnectionAsync(string remoteIp, string processName, string hostname, string country, CancellationToken ct = default);
    Task<bool> CheckAvailabilityAsync();
}

/// <summary>
/// Structured result from Ollama analysis.
/// </summary>
public record OllamaAnalysisResult(
    string Summary,
    string SecurityAssessment,
    string ProcessAnalysis,
    string Recommendations
);