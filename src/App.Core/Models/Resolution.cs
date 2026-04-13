namespace SmartNetworkTrafficAnalyzer.Core.Models;

/// <summary>
/// DNS resolution result for an IP address.
/// </summary>
public record Resolution(
    string Ip,
    string? Hostname,
    DateTimeOffset LastChecked
);