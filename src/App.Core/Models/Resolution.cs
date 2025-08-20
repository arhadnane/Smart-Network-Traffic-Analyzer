namespace SmartNetworkTrafficAnalyzer.Core.Models;

public record Resolution(
    string Ip,
    string? Hostname,
    DateTimeOffset LastChecked
);
