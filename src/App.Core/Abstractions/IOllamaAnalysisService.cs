using System.Text;
using System.Text.Json;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

public interface IOllamaAnalysisService
{
    Task<string> AnalyzeConnectionAsync(string remoteIp, string processName, string hostname, string country, CancellationToken ct = default);
}

public record OllamaAnalysisResult(
    string Summary,
    string SecurityAssessment,
    string ProcessAnalysis,
    string Recommendations
);
