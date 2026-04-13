namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Performs reverse DNS lookups for IP addresses.
/// </summary>
public interface IDnsResolver
{
    Task<string?> ReverseLookupAsync(string ip, CancellationToken ct);
}