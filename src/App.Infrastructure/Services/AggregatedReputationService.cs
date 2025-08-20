using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

public sealed class AggregatedReputationService : IReputationService
{
    private readonly IEnumerable<IReputationService> _providers;

    public AggregatedReputationService(IEnumerable<IReputationService> providers)
    {
        _providers = providers;
    }

    public async Task<Reputation> CheckAsync(string ip, CancellationToken ct)
    {
        RiskLevel best = RiskLevel.Clean;
        var notes = new Dictionary<string, string>();
        DateTimeOffset last = DateTimeOffset.MinValue;

        foreach (var p in _providers)
        {
            try
            {
                var r = await p.CheckAsync(ip, ct);
                if (r.RiskLevel > best) best = r.RiskLevel;
                foreach (var kv in r.Sources) notes[$"{p.GetType().Name}:{kv.Key}"] = kv.Value;
                if (r.LastChecked > last) last = r.LastChecked;
            }
            catch { }
        }

        return new Reputation(ip, best, notes, last == DateTimeOffset.MinValue ? DateTimeOffset.UtcNow : last);
    }
}
