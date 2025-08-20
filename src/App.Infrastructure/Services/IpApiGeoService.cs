using System.Net.Http.Json;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

public sealed class IpApiGeoService : IGeoService
{
    private static readonly HttpClient _http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

    public async Task<GeoInfo> LookupAsync(string ip, CancellationToken ct)
    {
        try
        {
            var url = $"http://ip-api.com/json/{ip}?fields=status,country,city,as,isp,query";
            var res = await _http.GetFromJsonAsync<IpApiResponse>(url, ct);
            if (res == null || !string.Equals(res.status, "success", StringComparison.OrdinalIgnoreCase))
                return new GeoInfo(ip, null, null, null, null, DateTimeOffset.UtcNow);
            var asn = string.IsNullOrWhiteSpace(res.@as) ? null : res.@as;
            var provider = string.IsNullOrWhiteSpace(res.isp) ? null : res.isp;
            return new GeoInfo(ip, res.country, res.city, asn, provider, DateTimeOffset.UtcNow);
        }
        catch
        {
            return new GeoInfo(ip, null, null, null, null, DateTimeOffset.UtcNow);
        }
    }

    private sealed record IpApiResponse(string status, string? country, string? city, string? @as, string? isp, string query);
}
