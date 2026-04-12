using System.Net;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Checks IP reputation against a CIDR-based blocklist loaded from disk.
/// </summary>
public sealed class BlocklistReputationService : IReputationService
{
    private readonly ILoggingService _logger;
    private readonly List<(IPAddress Network, int Prefix)> _cidrs;

    public BlocklistReputationService(ILoggingService logger)
        : this(logger, Path.Combine(AppContext.BaseDirectory, "data", "blocklist.txt"))
    {
    }

    public BlocklistReputationService(ILoggingService logger, string dataPath)
    {
        _logger = logger;
        _cidrs = LoadBlocklist(dataPath);
    }

    public Task<Reputation> CheckAsync(string ip, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);

        var level = RiskLevel.Clean;
        if (IPAddress.TryParse(ip, out var addr))
        {
            foreach (var (network, prefix) in _cidrs)
            {
                if (CidrMatcher.IsInCidr(addr, network, prefix))
                {
                    level = RiskLevel.High;
                    break;
                }
            }
        }

        var sources = new Dictionary<string, string>
        {
            ["Blocklist"] = level == RiskLevel.High ? "CIDR match" : "No match"
        };

        return Task.FromResult(new Reputation(ip, level, sources, DateTimeOffset.UtcNow));
    }

    private List<(IPAddress Network, int Prefix)> LoadBlocklist(string path)
    {
        var cidrs = new List<(IPAddress, int)>();

        if (!File.Exists(path))
        {
            _logger.Warn($"Blocklist file not found: {path}");
            return cidrs;
        }

        foreach (var line in File.ReadAllLines(path))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#'))
            {
                continue;
            }

            if (CidrMatcher.TryParseCidr(trimmed, out var net, out var prefix))
            {
                cidrs.Add((net, prefix));
            }
            else
            {
                _logger.Warn($"Invalid CIDR entry in blocklist: {trimmed}");
            }
        }

        _logger.Info($"Loaded {cidrs.Count} CIDR entries from blocklist");
        return cidrs;
    }
}

/// <summary>
/// Utility class for CIDR matching operations.
/// </summary>
internal static class CidrMatcher
{
    public static bool TryParseCidr(string cidr, out IPAddress network, out int prefix)
    {
        network = IPAddress.None;
        prefix = 0;
        var parts = cidr.Split('/');
        return parts.Length == 2
            && IPAddress.TryParse(parts[0], out network)
            && int.TryParse(parts[1], out prefix)
            && prefix is >= 0 and <= 128;
    }

    public static bool IsInCidr(IPAddress addr, IPAddress network, int prefix)
    {
        var addrBytes = addr.GetAddressBytes();
        var netBytes = network.GetAddressBytes();
        if (addrBytes.Length != netBytes.Length)
        {
            return false;
        }

        int fullBytes = prefix / 8;
        int remBits = prefix % 8;

        for (int i = 0; i < fullBytes; i++)
        {
            if (addrBytes[i] != netBytes[i])
            {
                return false;
            }
        }

        if (remBits == 0)
        {
            return true;
        }

        int mask = (byte)~(0xFF >> remBits);
        return (addrBytes[fullBytes] & mask) == (netBytes[fullBytes] & mask);
    }
}