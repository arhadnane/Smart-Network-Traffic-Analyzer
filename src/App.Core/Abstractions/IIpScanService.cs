namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Scans an IP address using free public APIs (no API key required).
/// </summary>
public interface IIpScanService
{
    Task<IpScanResult> ScanAsync(string ip, CancellationToken ct = default);
}

public record IpScanResult(
    string Ip,
    string? Isp,
    string? Organization,
    string? Domain,
    string? City,
    string? Region,
    string? Country,
    string? CountryCode,
    string? Timezone,
    double? Latitude,
    double? Longitude,
    bool? IsEu,
    string? FlagEmoji
);
