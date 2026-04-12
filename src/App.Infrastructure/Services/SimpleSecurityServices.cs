using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Categorizes IP addresses into known service types using prefix matching.
/// </summary>
public sealed class SimpleIPCategorizationService : IIPCategorizationService
{
    private static readonly IReadOnlyDictionary<string, string> KnownExactIPs = new Dictionary<string, string>
    {
        ["8.8.8.8"] = "DNS Public (Google)",
        ["1.1.1.1"] = "DNS Public (Cloudflare)",
        ["208.67.222.222"] = "DNS Public (OpenDNS)",
        ["4.2.2.2"] = "DNS Public (Level3)"
    };

    private static readonly (string Prefix, string Category, RiskLevel Risk, bool IsKnownGood)[] PrefixRules =
    [
        ("8.8.", "Google Services", RiskLevel.Low, true),
        ("172.217.", "Google Services", RiskLevel.Low, true),
        ("216.58.", "Google Services", RiskLevel.Low, true),
        ("151.101.", "Reddit/Fastly CDN", RiskLevel.Low, true),
        ("199.232.", "Reddit/Fastly CDN", RiskLevel.Low, true),
        ("13.", "Amazon AWS", RiskLevel.Low, true),
        ("54.", "Amazon AWS", RiskLevel.Low, true),
        ("52.", "Amazon AWS", RiskLevel.Low, true),
        ("40.", "Microsoft Azure", RiskLevel.Low, true),
        ("20.", "Microsoft Azure", RiskLevel.Low, true),
        ("157.240.", "Facebook/Meta", RiskLevel.Low, true),
        ("31.13.", "Facebook/Meta", RiskLevel.Low, true),
        ("185.220.", "Tor Exit Nodes", RiskLevel.High, false),
        ("194.187.", "VPN/Proxy anonyme", RiskLevel.Medium, false),
        ("45.142.", "Infrastructure suspecte", RiskLevel.High, false)
    ];

    public Task<IPCategory> CategorizeAsync(string ipAddress, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ipAddress);

        // Exact match first
        if (KnownExactIPs.TryGetValue(ipAddress, out var exactService))
        {
            return Task.FromResult(new IPCategory(exactService, "Known public service", RiskLevel.Low, IsKnownGood: true));
        }

        // Prefix matching
        foreach (var (prefix, category, risk, isKnownGood) in PrefixRules)
        {
            if (ipAddress.StartsWith(prefix, StringComparison.Ordinal))
            {
                return Task.FromResult(new IPCategory(category, $"IP range {prefix}.*", risk, isKnownGood));
            }
        }

        return Task.FromResult(new IPCategory("Unknown", "No matching category", RiskLevel.Clean));
    }
}

/// <summary>
/// Calculates a composite security score for a connection.
/// </summary>
public sealed class SimpleSecurityScoringService : ISecurityScoringService
{
    private const int BaseScore = 50;
    private const int MaxScore = 100;
    private const int MinScore = 0;

    public Task<SecurityScore> CalculateScoreAsync(string ipAddress, IPCategory category, SecurityAlert[] alerts, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ipAddress);

        var score = BaseScore;
        var factors = new Dictionary<string, double>();

        // Category adjustments
        if (category.IsKnownGood)
        {
            var bonus = category.Risk switch
            {
                RiskLevel.Low => 40,
                RiskLevel.Clean => 30,
                _ => 15
            };
            score += bonus;
            factors["CategoryBonus"] = bonus;
        }
        else if (category.IsKnownBad)
        {
            score -= 40;
            factors["CategoryPenalty"] = -40;
        }

        // Alert adjustments
        var alertPenalty = alerts.Length switch
        {
            0 => 0,
            1 => -10,
            2 => -20,
            _ => -35
        };
        score += alertPenalty;
        factors["AlertPenalty"] = alertPenalty;

        // Risk level override from alerts
        var worstAlertSeverity = alerts
            .Select(a => a.Severity)
            .DefaultIfEmpty(RiskLevel.Clean)
            .Max();

        var finalScore = Math.Clamp(score, MinScore, MaxScore);
        var level = DetermineRiskLevel(finalScore, worstAlertSeverity);

        var explanation = category.IsKnownGood
            ? $"{category.Name} is a known legitimate service"
            : category.IsKnownBad
                ? $"{category.Name} is flagged as dangerous"
                : $"IP {ipAddress} has no known reputation";

        return Task.FromResult(new SecurityScore(finalScore, level, explanation, factors));
    }

    private static RiskLevel DetermineRiskLevel(int score, RiskLevel alertSeverity)
    {
        if (alertSeverity >= RiskLevel.High)
        {
            return RiskLevel.High;
        }

        return score switch
        {
            >= 90 => RiskLevel.Clean,
            >= 70 => RiskLevel.Low,
            >= 50 => RiskLevel.Clean,
            >= 25 => RiskLevel.Medium,
            _ => RiskLevel.High
        };
    }
}

/// <summary>
/// Detects anomalies based on traffic volume, suspicious processes, and port analysis.
/// </summary>
public sealed class SimpleAnomalyDetectionService : IAnomalyDetectionService
{
    private readonly ILoggingService _logger;
    private readonly List<ConnectionRecord> _recentConnections = new();
    private const int MaxRecentConnections = 1000;

    private record ConnectionRecord(string RemoteIp, string ProcessName, long BytesOut, DateTime Timestamp);

    public SimpleAnomalyDetectionService(ILoggingService logger)
    {
        _logger = logger;
    }

    public void RecordConnection(string remoteIp, string processName, long bytesOut, DateTime connectionTime)
    {
        _recentConnections.Add(new ConnectionRecord(remoteIp, processName, bytesOut, connectionTime));
        if (_recentConnections.Count > MaxRecentConnections)
        {
            _recentConnections.RemoveAt(0);
        }
    }

    public Task<SecurityAlert[]> CheckAnomaliesAsync(string remoteIp, string processName, long bytesOut, DateTime connectionTime, CancellationToken ct = default)
    {
        var alerts = new List<SecurityAlert>();

        // Volume anomaly
        if (bytesOut > 100_000_000)
        {
            alerts.Add(new SecurityAlert(AlertType.VolumeAnomaly, RiskLevel.High, "Volume anormal",
                $"Volume de données anormal détecté (>100MB): {bytesOut:N0} bytes", connectionTime, remoteIp, processName));
        }
        else if (bytesOut > 10_000_000)
        {
            alerts.Add(new SecurityAlert(AlertType.VolumeAnomaly, RiskLevel.Medium, "Volume élevé",
                $"Volume de données élevé (>10MB): {bytesOut:N0} bytes", connectionTime, remoteIp, processName));
        }

        // Suspicious process
        var lowerProcess = processName.ToLowerInvariant();
        if (lowerProcess.Contains("unknown") || lowerProcess.Contains("temp") || lowerProcess.EndsWith(".tmp"))
        {
            alerts.Add(new SecurityAlert(AlertType.SuspiciousProcess, RiskLevel.High, "Processus suspect",
                $"Processus suspect détecté: {processName}", connectionTime, remoteIp, processName));
        }

        // Rapid connections from same IP
        var recentCount = _recentConnections
            .Count(r => r.RemoteIp == remoteIp && (connectionTime - r.Timestamp).TotalMinutes < 5);
        if (recentCount > 50)
        {
            alerts.Add(new SecurityAlert(AlertType.RapidConnections, RiskLevel.Medium, "Connexions rapides",
                $"{recentCount} connexions vers {remoteIp} en 5 minutes", connectionTime, remoteIp, processName));
        }

        return Task.FromResult(alerts.ToArray());
    }
}

/// <summary>
/// Combines categorization, scoring, and anomaly detection into a unified security analysis.
/// </summary>
public sealed class SecurityAnalysisService : ISecurityAnalysisService
{
    private readonly IIPCategorizationService _categorization;
    private readonly ISecurityScoringService _scoring;
    private readonly IAnomalyDetectionService _anomalyDetection;

    public SecurityAnalysisService(
        IIPCategorizationService categorization,
        ISecurityScoringService scoring,
        IAnomalyDetectionService anomalyDetection)
    {
        _categorization = categorization;
        _scoring = scoring;
        _anomalyDetection = anomalyDetection;
    }

    public async Task<SecurityAnalysisResult> AnalyzeConnectionAsync(string remoteIp, string processName, int port, long bytesOut, CancellationToken ct = default)
    {
        var category = await _categorization.CategorizeAsync(remoteIp, ct);
        var alerts = await _anomalyDetection.CheckAnomaliesAsync(remoteIp, processName, bytesOut, DateTime.UtcNow, ct);
        var score = await _scoring.CalculateScoreAsync(remoteIp, category, alerts, ct);

        var summary = score.Level switch
        {
            RiskLevel.Clean => $"Connection to {category.Name} appears safe (score: {score.Value})",
            RiskLevel.Low => $"Connection to {category.Name} is low risk (score: {score.Value})",
            RiskLevel.Medium => $"Connection to {category.Name} warrants attention (score: {score.Value})",
            RiskLevel.High => $"Connection to {category.Name} is HIGH RISK (score: {score.Value})",
            RiskLevel.Malicious => $"Connection to {category.Name} is MALICIOUS (score: {score.Value})",
            _ => $"Connection analysis: score {score.Value}"
        };

        return new SecurityAnalysisResult(category, score, alerts, summary);
    }
}

/// <summary>
/// Static threat intelligence lookup against known bad IPs and suspicious ranges.
/// </summary>
public sealed class ThreatIntelligenceService
{
    private static readonly IReadOnlyDictionary<string, string> KnownBadIPs = new Dictionary<string, string>
    {
        ["185.220.100.240"] = "Nœud de sortie Tor (AbuseIPDB)",
        ["45.142.214.191"] = "Botnet C&C détecté (VirusTotal)",
        ["103.224.182.251"] = "Distribution de malware (VirusTotal)",
        ["94.102.49.190"] = "Adresse IP compromise (AbuseIPDB)",
        ["198.98.51.189"] = "Activité de botnet (VirusTotal)"
    };

    private static readonly (string Prefix, string Description)[] SuspiciousRanges =
    [
        ("185.220.", "Réseau Tor Exit Node"),
        ("194.187.", "VPN/Proxy anonyme"),
        ("45.142.", "Infrastructure malveillante")
    ];

    public Task<string?> GetThreatIntelligenceAsync(string ipAddress)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ipAddress);

        if (KnownBadIPs.TryGetValue(ipAddress, out var threat))
        {
            return Task.FromResult<string?>(threat);
        }

        foreach (var (prefix, description) in SuspiciousRanges)
        {
            if (ipAddress.StartsWith(prefix, StringComparison.Ordinal))
            {
                return Task.FromResult<string?>($"IP suspecte: {description}");
            }
        }

        return Task.FromResult<string?>(null);
    }
}