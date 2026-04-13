using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Learns baseline traffic patterns and flags anomalies vs. normal behavior.
/// </summary>
public interface INetworkBaselineService
{
    /// <summary>Records a connection sample used to learn the baseline.</summary>
    void RecordSample(string processName, string remoteIp, int port, long bytesOut, DateTime timestamp);

    /// <summary>Evaluates current traffic against the learned baseline.</summary>
    Task<SecurityAlert[]> EvaluateAsync(string processName, string remoteIp, int port, long bytesOut, DateTime timestamp, CancellationToken ct = default);
}
