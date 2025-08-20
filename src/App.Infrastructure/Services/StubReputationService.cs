using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

public sealed class StubReputationService : IReputationService
{
    public Task<Reputation> CheckAsync(string ip, CancellationToken ct)
    {
        var level = ip.StartsWith("1.1.1.") ? RiskLevel.Low
            : ip.StartsWith("8.8.8.") ? RiskLevel.Medium
            : RiskLevel.Clean;
        var sources = new Dictionary<string, string>
        {
            { "Stub", $"Heuristic for {ip}" }
        };
        return Task.FromResult(new Reputation(ip, level, sources, DateTimeOffset.UtcNow));
    }
}
