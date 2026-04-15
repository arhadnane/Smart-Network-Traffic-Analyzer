namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Context about a network connection for AI analysis.
/// </summary>
public record ConnectionAnalysisContext(
    string RemoteIp,
    string ProcessName,
    int ProcessId,
    string? Hostname,
    string? Country,
    int RemotePort,
    string Direction,
    long BytesIn,
    long BytesOut,
    string? ProcessPath = null,
    string? ProcessDescription = null,
    string? ProcessCompany = null,
    string? ProcessWindowTitle = null
);

/// <summary>
/// Connects to a local Ollama instance for AI-powered connection analysis.
/// </summary>
public interface IOllamaAnalysisService
{
    string SelectedModel { get; }
    Task<string> AnalyzeConnectionAsync(ConnectionAnalysisContext context, CancellationToken ct = default);
    Task<bool> CheckAvailabilityAsync();
    Task<IReadOnlyList<string>> GetAvailableModelsAsync(CancellationToken ct = default);
    void SetSelectedModel(string model);
}