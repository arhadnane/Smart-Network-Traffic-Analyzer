using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Detects C2 beaconing patterns — regular interval connections typical of malware command-and-control.
/// </summary>
public interface IBeaconingDetector
{
    /// <summary>Records a connection timestamp for analysis.</summary>
    void RecordConnection(string remoteIp, string processName, DateTime timestamp);

    /// <summary>Analyzes recorded connections for beaconing behavior.</summary>
    Task<SecurityAlert[]> DetectBeaconingAsync(string remoteIp, CancellationToken ct = default);
}
