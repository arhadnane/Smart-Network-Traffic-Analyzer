using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Stub DNS resolver that returns fake results for known test IPs.
/// </summary>
public sealed class StubDnsResolver : IDnsResolver
{
    public Task<string?> ReverseLookupAsync(string ip, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);
        var result = ip.StartsWith("8.8.8.", StringComparison.Ordinal) ? "dns.google" : null;
        return Task.FromResult(result);
    }
}