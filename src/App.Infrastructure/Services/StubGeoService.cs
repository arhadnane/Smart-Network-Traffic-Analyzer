using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Stub geolocation service that returns hardcoded results for known test IPs.
/// </summary>
public sealed class StubGeoService : IGeoService
{
    public Task<GeoInfo> LookupAsync(string ip, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);

        string? country = ip.StartsWith("8.8.", StringComparison.Ordinal) ? "US" : null;
        string? asn = ip.StartsWith("1.1.", StringComparison.Ordinal) ? "AS13335" : null;
        string? provider = ip.StartsWith("1.1.", StringComparison.Ordinal)
            ? "Cloudflare"
            : ip.StartsWith("8.8.", StringComparison.Ordinal)
                ? "Google"
                : null;

        return Task.FromResult(new GeoInfo(ip, country, null, asn, provider, DateTimeOffset.UtcNow));
    }
}