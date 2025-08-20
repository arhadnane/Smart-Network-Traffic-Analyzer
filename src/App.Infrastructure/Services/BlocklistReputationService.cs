using System.Net;
using System.Net.Sockets;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

public sealed class BlocklistReputationService : IReputationService
{
    private readonly string _dataPath;
    private readonly List<(IPAddress Network, int Prefix)> _cidrs = new();

    public BlocklistReputationService()
    {
        var baseDir = AppContext.BaseDirectory;
        _dataPath = Path.Combine(baseDir, "data", "blocklist.txt");
        if (File.Exists(_dataPath))
        {
            foreach (var line in File.ReadAllLines(_dataPath))
            {
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#")) continue;
                if (TryParseCidr(trimmed, out var net, out var prefix))
                {
                    _cidrs.Add((net, prefix));
                }
            }
        }
    }

    public Task<Reputation> CheckAsync(string ip, CancellationToken ct)
    {
        var level = RiskLevel.Clean;
        if (IPAddress.TryParse(ip, out var addr))
        {
            foreach (var (network, prefix) in _cidrs)
            {
                if (IsInCidr(addr, network, prefix))
                {
                    level = RiskLevel.High;
                    break;
                }
            }
        }

        var sources = new Dictionary<string, string>
        {
            { "Blocklist", level == RiskLevel.High ? "CIDR match" : "No match" }
        };
        return Task.FromResult(new Reputation(ip, level, sources, DateTimeOffset.UtcNow));
    }

    private static bool TryParseCidr(string cidr, out IPAddress network, out int prefix)
    {
        network = IPAddress.None;
        prefix = 0;
        var parts = cidr.Split('/');
        if (parts.Length != 2) return false;
        if (!IPAddress.TryParse(parts[0], out network)) return false;
        if (!int.TryParse(parts[1], out prefix)) return false;
        return true;
    }

    private static bool IsInCidr(IPAddress addr, IPAddress network, int prefix)
    {
        var addrBytes = addr.GetAddressBytes();
        var netBytes = network.GetAddressBytes();
        if (addrBytes.Length != netBytes.Length) return false;
        int fullBytes = prefix / 8;
        int remBits = prefix % 8;
        for (int i = 0; i < fullBytes; i++)
        {
            if (addrBytes[i] != netBytes[i]) return false;
        }
        if (remBits == 0) return true;
        int mask = (byte)~(0xFF >> remBits);
        return (addrBytes[fullBytes] & mask) == (netBytes[fullBytes] & mask);
    }
}
