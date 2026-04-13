using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Aggregates reputation results from multiple providers, returning the highest risk level found.
/// </summary>
public sealed class AggregatedReputationService : IReputationService
{
    private readonly IReadOnlyList<IReputationService> _providers;
    private readonly ILoggingService _logger;

    public AggregatedReputationService(IEnumerable<IReputationService> providers, ILoggingService logger)
    {
        _providers = providers.ToList().AsReadOnly();
        _logger = logger;
    }

    public async Task<Reputation> CheckAsync(string ip, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);

        RiskLevel best = RiskLevel.Clean;
        var notes = new Dictionary<string, string>();
        DateTimeOffset last = DateTimeOffset.MinValue;

        foreach (var provider in _providers)
        {
            try
            {
                var result = await provider.CheckAsync(ip, ct);
                if (result.RiskLevel > best)
                {
                    best = result.RiskLevel;
                }

                foreach (var kv in result.Sources)
                {
                    notes[$"{provider.GetType().Name}:{kv.Key}"] = kv.Value;
                }

                if (result.LastChecked > last)
                {
                    last = result.LastChecked;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.Warn($"Reputation provider {provider.GetType().Name} failed for {ip}: {ex.Message}");
            }
        }

        return new Reputation(ip, best, notes, last == DateTimeOffset.MinValue ? DateTimeOffset.UtcNow : last);
    }
}