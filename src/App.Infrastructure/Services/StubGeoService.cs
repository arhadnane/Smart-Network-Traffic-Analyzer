using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

public sealed class StubGeoService : IGeoService
{
    public Task<GeoInfo> LookupAsync(string ip, CancellationToken ct)
    {
        var country = ip.StartsWith("8.8.") ? "US" : null;
        var asn = ip.StartsWith("1.1.") ? "AS13335" : null;
        var provider = ip.StartsWith("1.1.") ? "Cloudflare" : (ip.StartsWith("8.8.") ? "Google" : null);
        return Task.FromResult(new GeoInfo(ip, country, null, asn, provider, DateTimeOffset.UtcNow));
    }
}
