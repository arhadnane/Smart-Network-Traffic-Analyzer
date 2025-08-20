namespace SmartNetworkTrafficAnalyzer.Core.Models;

public enum RiskLevel
{
    Clean,
    Low,
    Medium,
    High,
    Malicious
}

public record Reputation(
    string Ip,
    RiskLevel RiskLevel,
    IReadOnlyDictionary<string, string> Sources,
    DateTimeOffset LastChecked
);
