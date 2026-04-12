using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Performs security analysis on a network connection.
/// </summary>
public interface ISecurityAnalysisService
{
    Task<SecurityAnalysisResult> AnalyzeConnectionAsync(string remoteIp, string processName, int port, long bytesOut, CancellationToken ct = default);
}

/// <summary>
/// Detects anomalous connection patterns over time.
/// </summary>
public interface IAnomalyDetectionService
{
    Task<SecurityAlert[]> CheckAnomaliesAsync(string remoteIp, string processName, long bytesOut, DateTime connectionTime, CancellationToken ct = default);
    void RecordConnection(string remoteIp, string processName, long bytesOut, DateTime connectionTime);
}

/// <summary>
/// Categorizes an IP address into a known service type.
/// </summary>
public interface IIPCategorizationService
{
    Task<IPCategory> CategorizeAsync(string ipAddress, CancellationToken ct = default);
}

/// <summary>
/// Calculates a composite security score for a connection.
/// </summary>
public interface ISecurityScoringService
{
    Task<SecurityScore> CalculateScoreAsync(string ipAddress, IPCategory category, SecurityAlert[] alerts, CancellationToken ct = default);
}

/// <summary>
/// Combined result from all security analysis services.
/// </summary>
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
    int Value,
    RiskLevel Level,
    string Explanation,
    IReadOnlyDictionary<string, double> FactorScores
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