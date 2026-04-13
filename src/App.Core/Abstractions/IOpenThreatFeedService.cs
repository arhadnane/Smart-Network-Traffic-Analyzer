namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Queries free, open threat intelligence feeds (no API key required) for IP reputation data.
/// </summary>
public interface IOpenThreatFeedService
{
    /// <summary>Checks an IP against open threat feeds. Returns human-readable findings or null.</summary>
    Task<string?> CheckIpAsync(string ipAddress, CancellationToken ct = default);
}
