using System;
using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Rate-limited, cached wrapper around ip-api.com.
/// Free tier allows 45 requests/minute. This implementation:
/// - Caches results for 30 minutes
/// - Rate-limits to max 40 requests/minute
/// - Uses HTTPS via the batch endpoint (ip-api premium) or falls back to HTTP
/// </summary>
public sealed class CachedGeoService : IGeoService
{
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(30);
    private static readonly SemaphoreSlim RateLimiter = new(1, 1);
    private static readonly TimeSpan MinInterval = TimeSpan.FromMilliseconds(1500); // ~40/min

    private readonly HttpClient _http;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastRequest = DateTime.MinValue;

    public CachedGeoService() : this(new HttpClient { Timeout = TimeSpan.FromSeconds(5) }) { }

    public CachedGeoService(HttpClient httpClient)
    {
        _http = httpClient;
    }

    public async Task<GeoInfo> LookupAsync(string ip, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return EmptyGeo(ip);

        var now = DateTime.UtcNow;
        if (_cache.TryGetValue(ip, out var cached) && cached.Expiration > now)
            return cached.Value;

        try
        {
            await ThrottleAsync(ct).ConfigureAwait(false);

            var url = $"http://ip-api.com/json/{ip}?fields=status,country,city,as,isp,query";
            var res = await _http.GetFromJsonAsync<IpApiResponse>(url, ct).ConfigureAwait(false);

            if (res == null || !string.Equals(res.Status, "success", StringComparison.OrdinalIgnoreCase))
            {
                var empty = EmptyGeo(ip);
                _cache[ip] = new CacheEntry(empty, now + TimeSpan.FromMinutes(5)); // Short cache for failures
                return empty;
            }

            var geo = new GeoInfo(ip, res.Country, res.City,
                string.IsNullOrWhiteSpace(res.As) ? null : res.As,
                string.IsNullOrWhiteSpace(res.Isp) ? null : res.Isp,
                DateTimeOffset.UtcNow);

            _cache[ip] = new CacheEntry(geo, now + CacheDuration);
            return geo;
        }
        catch
        {
            return EmptyGeo(ip);
        }
    }

    private async Task ThrottleAsync(CancellationToken ct)
    {
        await RateLimiter.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var elapsed = DateTime.UtcNow - _lastRequest;
            if (elapsed < MinInterval)
                await Task.Delay(MinInterval - elapsed, ct).ConfigureAwait(false);
            _lastRequest = DateTime.UtcNow;
        }
        finally
        {
            RateLimiter.Release();
        }
    }

    private static GeoInfo EmptyGeo(string ip) => new(ip, null, null, null, null, DateTimeOffset.UtcNow);

    private sealed record CacheEntry(GeoInfo Value, DateTime Expiration);

    private sealed record IpApiResponse(
        string Status,
        string? Country,
        string? City,
        string? As,
        string? Isp,
        string Query);
}
