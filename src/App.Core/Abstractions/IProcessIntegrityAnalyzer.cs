using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Analyzes running processes for signs of compromise: suspicious paths, masquerading, anomalous behavior.
/// </summary>
public interface IProcessIntegrityAnalyzer
{
    /// <summary>Analyzes a process by name and PID for suspicious indicators.</summary>
    Task<SecurityAlert[]> AnalyzeProcessAsync(string processName, int processId, string remoteIp, CancellationToken ct = default);
}
