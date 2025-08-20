using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

public sealed class StubDnsResolver : IDnsResolver
{
    public Task<string?> ReverseLookupAsync(string ip, CancellationToken ct)
    {
        // Simple stub: pretend some IPs have PTRs
        if (ip.StartsWith("8.8.8.")) return Task.FromResult<string?>("dns.google");
        return Task.FromResult<string?>(null);
    }
}
