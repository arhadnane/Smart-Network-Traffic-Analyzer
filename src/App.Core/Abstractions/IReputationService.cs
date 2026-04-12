using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Checks IP reputation against blocklists and threat feeds.
/// </summary>
public interface IReputationService
{
    Task<Reputation> CheckAsync(string ip, CancellationToken ct);
}