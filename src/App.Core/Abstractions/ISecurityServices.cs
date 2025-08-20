using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

public interface ISecurityAnalysisService
{
    Task<SecurityAnalysisResult> AnalyzeConnectionAsync(string remoteIp, string processName, int port);
}

public interface IAnomalyDetectionService
{
    Task<SecurityAlert[]> CheckAnomaliesAsync(string remoteIp, string processName, long bytesOut, DateTime connectionTime);
    void RecordConnection(string remoteIp, string processName, long bytesOut, DateTime connectionTime);
}

public interface IIPCategorizationService
{
    Task<IPCategory> CategorizeAsync(string ipAddress);
}

public interface ISecurityScoringService
{
    Task<SecurityScore> CalculateScoreAsync(string ipAddress, IPCategory category, SecurityAlert[] alerts);
}

public record SecurityAnalysisResult(
    IPCategory Category,
    SecurityScore Score,
    SecurityAlert[] Alerts,
    string Summary
);

public record IPCategory(
    string Name,
    string Description,
    RiskLevel Risk,
    bool IsKnownGood = false,
    bool IsKnownBad = false
);

public record SecurityScore(
    int Value, // 0-100
    RiskLevel Level,
    string Explanation,
    Dictionary<string, double> FactorScores
);

public record SecurityAlert(
    AlertType Type,
    RiskLevel Severity,
    string Title,
    string Description,
    DateTime Timestamp,
    string? RelatedIP = null,
    string? RelatedProcess = null
);

public enum AlertType
{
    VolumeAnomaly,
    RapidConnections,
    SuspiciousProcess,
    TorConnection,
    MalwareIP,
    UnknownDestination,
    PortScanning
}
