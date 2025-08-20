using System.Net;
using System.Net.Sockets;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

public sealed class SystemDnsResolver : IDnsResolver
{
    public async Task<string?> ReverseLookupAsync(string ip, CancellationToken ct)
    {
        if (!IPAddress.TryParse(ip, out var address)) return null;
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
