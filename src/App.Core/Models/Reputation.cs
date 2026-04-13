namespace SmartNetworkTrafficAnalyzer.Core.Models;

public enum RiskLevel
{
    Clean,
    Low,
    Medium,
    High,
    Malicious
}

/// <summary>
/// IP reputation check result aggregated from multiple providers.
/// </summary>
public record Reputation(
    string Ip,
    RiskLevel RiskLevel,
    IReadOnlyDictionary<string, string> Sources,
    DateTimeOffset LastChecked
);