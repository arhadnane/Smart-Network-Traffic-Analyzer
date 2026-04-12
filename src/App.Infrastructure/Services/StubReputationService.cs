using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Stub reputation service that returns heuristic results for known test IPs.
/// </summary>
public sealed class StubReputationService : IReputationService
{
    public Task<Reputation> CheckAsync(string ip, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);

        var level = ip.StartsWith("1.1.1.", StringComparison.Ordinal) ? RiskLevel.Low
            : ip.StartsWith("8.8.8.", StringComparison.Ordinal) ? RiskLevel.Medium
            : RiskLevel.Clean;

        var sources = new Dictionary<string, string>
        {
            ["Stub"] = $"Heuristic for {ip}"
        };

        return Task.FromResult(new Reputation(ip, level, sources, DateTimeOffset.UtcNow));
    }
}