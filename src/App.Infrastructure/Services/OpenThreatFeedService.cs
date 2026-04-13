using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Queries free, open threat intelligence feeds that require NO API key:
/// - abuse.ch URLhaus API (malware URLs/IPs)
/// - abuse.ch ThreatFox API (IOCs)
/// Rate-limited with in-memory cache to be a good API citizen.
/// </summary>
public sealed class OpenThreatFeedService : IOpenThreatFeedService
{
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);
    private static readonly SemaphoreSlim RateLimiter = new(1, 1);
    private static readonly TimeSpan MinRequestInterval = TimeSpan.FromSeconds(2);

    private readonly HttpClient _http;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastRequest = DateTime.MinValue;

    public OpenThreatFeedService(HttpClient httpClient)
    {
        _http = httpClient;
        _http.Timeout = RequestTimeout;
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("SmartNetworkTrafficAnalyzer/1.0");
    }

    public async Task<string?> CheckIpAsync(string ipAddress, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            return null;

        var now = DateTime.UtcNow;
        if (_cache.TryGetValue(ipAddress, out var cached) && cached.Expiration > now)
            return cached.Value;

        var findings = new List<string>();

        // Query URLhaus for this IP
        var urlhausResult = await QueryUrlhausAsync(ipAddress, ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(urlhausResult))
            findings.Add(urlhausResult);

        // Query ThreatFox for this IP
        var threatFoxResult = await QueryThreatFoxAsync(ipAddress, ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(threatFoxResult))
            findings.Add(threatFoxResult);

        string? result = findings.Count > 0 ? string.Join(" | ", findings) : null;
        _cache[ipAddress] = new CacheEntry(result, now + CacheDuration);

        return result;
    }

    private async Task<string?> QueryUrlhausAsync(string ip, CancellationToken ct)
    {
        try
        {
            await ThrottleAsync(ct).ConfigureAwait(false);

            var content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("host", ip) });
            var response = await _http.PostAsync("https://urlhaus-api.abuse.ch/v1/host/", content, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return null;

            var json = await response.Content.ReadFromJsonAsync<UrlhausResponse>(cancellationToken: ct).ConfigureAwait(false);

            if (json?.QueryStatus == "no_results" || json?.UrlCount == null || json.UrlCount == "0")
                return null;

            var urlCount = json.UrlCount;
            var tags = json.Urls?
                .Where(u => u.Tags != null)
                .SelectMany(u => u.Tags!)
                .Distinct()
                .Take(5)
                .ToArray() ?? Array.Empty<string>();

            var tagStr = tags.Length > 0 ? $" (tags: {string.Join(", ", tags)})" : "";
            return $"URLhaus: {urlCount} URL(s) malveillante(s) hebergee(s){tagStr}";
        }
        catch
        {
            return null;
        }
    }

    private async Task<string?> QueryThreatFoxAsync(string ip, CancellationToken ct)
    {
        try
        {
            await ThrottleAsync(ct).ConfigureAwait(false);

            var payload = new { query = "search_ioc", search_term = ip };
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await _http.PostAsync("https://threatfox-api.abuse.ch/api/v1/", content, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return null;

            var json = await response.Content.ReadFromJsonAsync<ThreatFoxResponse>(cancellationToken: ct).ConfigureAwait(false);

            if (json?.QueryStatus != "ok" || json.Data == null || json.Data.Count == 0)
                return null;

            var malwareTypes = json.Data
                .Select(d => d.MalwarePrintable)
                .Where(m => !string.IsNullOrWhiteSpace(m))
                .Distinct()
                .Take(3)
                .ToArray();

            var threatTypes = json.Data
                .Select(d => d.ThreatType)
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Distinct()
                .Take(3)
                .ToArray();

            var parts = new List<string>();
            if (malwareTypes.Length > 0) parts.Add($"malware: {string.Join(", ", malwareTypes)}");
            if (threatTypes.Length > 0) parts.Add($"type: {string.Join(", ", threatTypes)}");

            return $"ThreatFox: {json.Data.Count} IOC(s) trouves ({string.Join("; ", parts)})";
        }
        catch
        {
            return null;
        }
    }

    private async Task ThrottleAsync(CancellationToken ct)
    {
        await RateLimiter.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var elapsed = DateTime.UtcNow - _lastRequest;
            if (elapsed < MinRequestInterval)
            {
                await Task.Delay(MinRequestInterval - elapsed, ct).ConfigureAwait(false);
            }
            _lastRequest = DateTime.UtcNow;
        }
        finally
        {
            RateLimiter.Release();
        }
    }

    private sealed record CacheEntry(string? Value, DateTime Expiration);

    // -- URLhaus models --
    private sealed class UrlhausResponse
    {
        [JsonPropertyName("query_status")]
        public string? QueryStatus { get; set; }

        [JsonPropertyName("urlhaus_reference")]
        public string? Reference { get; set; }

        [JsonPropertyName("url_count")]
        public string? UrlCount { get; set; }

        [JsonPropertyName("urls")]
        public List<UrlhausUrl>? Urls { get; set; }
    }

    private sealed class UrlhausUrl
    {
        [JsonPropertyName("url_status")]
        public string? UrlStatus { get; set; }

        [JsonPropertyName("threat")]
        public string? Threat { get; set; }

        [JsonPropertyName("tags")]
        public List<string>? Tags { get; set; }
    }

    // -- ThreatFox models --
    private sealed class ThreatFoxResponse
    {
        [JsonPropertyName("query_status")]
        public string? QueryStatus { get; set; }

        [JsonPropertyName("data")]
        public List<ThreatFoxIoc>? Data { get; set; }
    }

    private sealed class ThreatFoxIoc
    {
        [JsonPropertyName("malware_printable")]
        public string? MalwarePrintable { get; set; }

        [JsonPropertyName("threat_type")]
        public string? ThreatType { get; set; }

        [JsonPropertyName("confidence_level")]
        public int? ConfidenceLevel { get; set; }
    }
}
