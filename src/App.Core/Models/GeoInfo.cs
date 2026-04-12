namespace SmartNetworkTrafficAnalyzer.Core.Models;

/// <summary>
/// Geolocation information for an IP address.
/// </summary>
public record GeoInfo(
    string Ip,
    string? Country,
    string? City,
    string? Asn,
    string? Provider,
    DateTimeOffset LastChecked
);