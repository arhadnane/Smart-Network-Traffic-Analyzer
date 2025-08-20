using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

public interface IReputationService
{
    Task<Reputation> CheckAsync(string ip, CancellationToken ct);
}
