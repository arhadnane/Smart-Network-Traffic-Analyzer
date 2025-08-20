namespace SmartNetworkTrafficAnalyzer.Core.Models;

public record GeoInfo(
    string Ip,
    string? Country,
    string? City,
    string? Asn,
    string? Provider,
    DateTimeOffset LastChecked
);
