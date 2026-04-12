using System.Net.Http.Json;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Geolocation service using the free ip-api.com endpoint.
/// Rate-limited to 45 requests/minute on the free tier.
/// </summary>
public sealed class IpApiGeoService : IGeoService
{
    private readonly HttpClient _http;
    private readonly ILoggingService _logger;

    public IpApiGeoService(HttpClient httpClient, ILoggingService logger)
    {
        _http = httpClient;
        _http.Timeout = TimeSpan.FromSeconds(5);
        _logger = logger;
    }

    public async Task<GeoInfo> LookupAsync(string ip, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);

        try
        {
            var url = $"http://ip-api.com/json/{ip}?fields=status,message,country,city,as,isp,query";
            var res = await _http.GetFromJsonAsync<IpApiResponse>(url, ct);

            if (res is null || !string.Equals(res.status, "success", StringComparison.OrdinalIgnoreCase))
            {
                var msg = res?.message ?? "Unknown error";
                _logger.Warn($"ip-api.com lookup failed for {ip}: {msg}");
                return new GeoInfo(ip, null, null, null, null, DateTimeOffset.UtcNow);
            }

            var asn = string.IsNullOrWhiteSpace(res.@as) ? null : res.@as;
            var provider = string.IsNullOrWhiteSpace(res.isp) ? null : res.isp;
            return new GeoInfo(ip, res.country, res.city, asn, provider, DateTimeOffset.UtcNow);
        }
        catch (HttpRequestException ex)
        {
            _logger.Warn($"Geo lookup HTTP error for {ip}: {ex.Message}");
            return new GeoInfo(ip, null, null, null, null, DateTimeOffset.UtcNow);
        }
        catch (TaskCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (TaskCanceledException ex)
        {
            _logger.Warn($"Geo lookup timeout for {ip}: {ex.Message}");
            return new GeoInfo(ip, null, null, null, null, DateTimeOffset.UtcNow);
        }
    }

    private sealed record IpApiResponse(
        string status,
        string? message,
        string? country,
        string? city,
        string? @as,
        string? isp,
        string query
    );
}