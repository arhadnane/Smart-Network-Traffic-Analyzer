using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

// Service de catégorisation des IPs
public class SimpleIPCategorizationService
{
    private readonly Dictionary<string, string> _knownServices = new()
    {
        ["8.8.8.8"] = "DNS Public (Google)",
        ["1.1.1.1"] = "DNS Public (Cloudflare)",
        ["208.67.222.222"] = "DNS Public (OpenDNS)",
        ["4.2.2.2"] = "DNS Public (Level3)"
    };

    public async Task<string> CategorizeAsync(string ipAddress)
    {
        if (_knownServices.TryGetValue(ipAddress, out var service))
            return service;

        // Analyse par plages IP
        if (ipAddress.StartsWith("8.8."))
            return "Google Services";
        if (ipAddress.StartsWith("151.101.") || ipAddress.StartsWith("199.232."))
            return "Reddit/Fastly CDN";
        if (ipAddress.StartsWith("13.") || ipAddress.StartsWith("54.") || ipAddress.StartsWith("52."))
            return "Amazon AWS";
        if (ipAddress.StartsWith("40.") || ipAddress.StartsWith("20."))
            return "Microsoft Azure";
        if (ipAddress.StartsWith("172.217.") || ipAddress.StartsWith("216.58."))
            return "Google Services";
        if (ipAddress.StartsWith("157.240.") || ipAddress.StartsWith("31.13."))
            return "Facebook/Meta";

        await Task.Delay(10); // Simulation d'appel API
        return "Service Inconnu";
    }
}

// Service de scoring de sécurité
public class SimpleSecurityScoringService
{
    public static int CalculateScore(string ipAddress, string category, string processName, int port, long bytesOut)
    {
        var score = 50; // Score neutre de base

        // Bonus pour services connus
        if (category.Contains("Google") || category.Contains("Microsoft"))
            score += 40;
        else if (category.Contains("DNS Public"))
            score += 35;
        else if (category.Contains("CDN") || category.Contains("AWS") || category.Contains("Azure"))
            score += 20;
        else if (category.Contains("Facebook") || category.Contains("Reddit"))
            score += 15;

        // Pénalités pour processus suspects
        if (processName.ToLower().Contains("unknown") || 
            processName.ToLower().Contains("temp") ||
            processName.EndsWith(".tmp"))
            score -= 30;

        // Pénalités pour ports non-standards
        if (port != 80 && port != 443 && port != 53 && port != 21 && port != 22)
            score -= 10;

        // Ajustement pour volume de données
        if (bytesOut > 100_000_000) // > 100MB
            score -= 15;
        else if (bytesOut > 10_000_000) // > 10MB
            score -= 5;

        return Math.Max(0, Math.Min(100, score));
    }
}

// Service de détection d'alertes
public class SimpleAnomalyDetectionService
{
    public static async Task<List<string>> DetectAlertsAsync(string ipAddress, string processName, int port, long bytesOut)
    {
        var alerts = new List<string>();

        // Détection de volume anormal
        if (bytesOut > 100_000_000)
            alerts.Add("🔴 Volume de données anormal (>100MB)");
        else if (bytesOut > 10_000_000)
            alerts.Add("🟡 Volume de données élevé (>10MB)");

        // Détection de processus suspect
        if (processName.ToLower().Contains("unknown") ||
            processName.ToLower().Contains("temp") ||
            processName.EndsWith(".tmp") ||
            processName.ToLower().Contains("svchost") && port != 53)
            alerts.Add("🟠 Processus suspect détecté");

        // Détection de ports suspects
        var suspiciousPorts = new[] { 6667, 6697, 1337, 31337, 4444, 5555, 9050, 9051 };
        if (suspiciousPorts.Contains(port))
            alerts.Add("🔴 Port suspect détecté");

        var dangerousPorts = new[] { 23, 135, 139, 445, 1433, 3389 };
        if (dangerousPorts.Contains(port))
            alerts.Add("🟠 Port potentiellement dangereux");

        await Task.Delay(10); // Simulation d'analyse
        return alerts;
    }
}

// Service de threat intelligence simplifié
public class SimpleThreatIntelligenceService
{
    private readonly Dictionary<string, string> _knownBadIPs = new()
    {
        ["185.220.100.240"] = "Nœud de sortie Tor (AbuseIPDB)",
        ["45.142.214.191"] = "Botnet C&C détecté (VirusTotal)",
        ["103.224.182.251"] = "Distribution de malware (VirusTotal)",
        ["94.102.49.190"] = "Adresse IP compromise (AbuseIPDB)",
        ["198.98.51.189"] = "Activité de botnet (VirusTotal)"
    };

    private readonly Dictionary<string, string> _suspiciousRanges = new()
    {
        ["185.220."] = "Réseau Tor Exit Node",
        ["194.187."] = "VPN/Proxy anonyme",
        ["45.142."] = "Infrastructure malveillante"
    };

    public async Task<string?> GetThreatIntelligenceAsync(string ipAddress)
    {
        // Vérification directe des IPs connues
        if (_knownBadIPs.TryGetValue(ipAddress, out var threat))
            return threat;

        // Vérification des plages suspectes
        foreach (var range in _suspiciousRanges)
        {
            if (ipAddress.StartsWith(range.Key))
                return $"IP suspecte: {range.Value}";
        }

        await Task.Delay(50); // Simulation d'appel API
        return null;
    }
}
