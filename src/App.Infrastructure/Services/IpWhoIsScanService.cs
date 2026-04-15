using System.Text.Json;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// IP scanning service using ipwho.is — 100 % free, no API key.
/// Rate limit: 10 000 requests/month.
/// </summary>
public sealed class IpWhoIsScanService : IIpScanService
{
    private readonly HttpClient _http;
    private readonly ILoggingService _logger;

    public IpWhoIsScanService(HttpClient httpClient, ILoggingService logger)
    {
        _http = httpClient;
        _http.Timeout = TimeSpan.FromSeconds(10);
        _logger = logger;
    }

    public async Task<IpScanResult> ScanAsync(string ip, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);

        try
        {
            var url = $"https://ipwho.is/{Uri.EscapeDataString(ip)}";
            var response = await _http.GetAsync(url, ct);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(ct);
            var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("success", out var success) && !success.GetBoolean())
            {
                var msg = root.TryGetProperty("message", out var m) ? m.GetString() : "Unknown error";
                _logger.Warn($"ipwho.is scan failed for {ip}: {msg}");
                return EmptyResult(ip);
            }

            string? isp = null, org = null, domain = null;
            if (root.TryGetProperty("connection", out var conn))
            {
                isp = GetString(conn, "isp");
                org = GetString(conn, "org");
                domain = GetString(conn, "domain");
            }

            string? timezoneId = null;
            if (root.TryGetProperty("timezone", out var tz))
            {
                timezoneId = GetString(tz, "id");
            }

            string? flagEmoji = null;
            if (root.TryGetProperty("flag", out var flag))
            {
                flagEmoji = GetString(flag, "emoji");
            }

            return new IpScanResult(
                Ip: ip,
                Isp: isp,
                Organization: org,
                Domain: domain,
                City: GetString(root, "city"),
                Region: GetString(root, "region"),
                Country: GetString(root, "country"),
                CountryCode: GetString(root, "country_code"),
                Timezone: timezoneId,
                Latitude: root.TryGetProperty("latitude", out var lat) && lat.ValueKind == JsonValueKind.Number ? lat.GetDouble() : null,
                Longitude: root.TryGetProperty("longitude", out var lon) && lon.ValueKind == JsonValueKind.Number ? lon.GetDouble() : null,
                IsEu: root.TryGetProperty("is_eu", out var eu) && (eu.ValueKind == JsonValueKind.True || eu.ValueKind == JsonValueKind.False) ? eu.GetBoolean() : null,
                FlagEmoji: flagEmoji
            );
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.Warn($"IP scan error for {ip}: {ex.Message}");
            return EmptyResult(ip);
        }
    }

    private static IpScanResult EmptyResult(string ip) =>
        new(ip, null, null, null, null, null, null, null, null, null, null, null, null);

    private static string? GetString(JsonElement element, string property)
    {
        if (element.TryGetProperty(property, out var val) && val.ValueKind == JsonValueKind.String)
        {
            var s = val.GetString();
            return string.IsNullOrWhiteSpace(s) ? null : s;
        }
        return null;
    }
}
