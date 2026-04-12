using System.Net;
using System.Net.Sockets;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// DNS resolver using the system's built-in reverse DNS lookup.
/// </summary>
public sealed class SystemDnsResolver : IDnsResolver
{
    public async Task<string?> ReverseLookupAsync(string ip, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);
        if (!IPAddress.TryParse(ip, out var address))
        {
            return null;
        }

        try
        {
            var hostEntry = await Dns.GetHostEntryAsync(address);
            return hostEntry.HostName;
        }
        catch (SocketException)
        {
            return null;
        }
    }
}