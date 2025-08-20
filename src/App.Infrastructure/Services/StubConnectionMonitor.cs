using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

public sealed class StubConnectionMonitor : IConnectionMonitor
{
    public async IAsyncEnumerable<Connection> GetLiveConnectionsAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        Console.WriteLine("[StubConnectionMonitor] WARNING: Using STUB data, not real connections!");
        var rnd = new Random();
        var start = DateTimeOffset.UtcNow;
        int i = 0;
        while (!ct.IsCancellationRequested && i < 10)
        {
            i++;
            var ip = i % 2 == 0 ? $"8.8.8.{i}" : $"1.1.1.{i}";
            yield return new Connection(
                Id: Guid.NewGuid().ToString("n"),
                SequentialId: i,
                FirstSeen: start,
                LastSeen: DateTimeOffset.UtcNow,
                Direction: i % 2 == 0 ? Direction.Outbound : Direction.Inbound,
                LocalEndpoint: "127.0.0.1:5000",
                RemoteIp: ip,
                RemotePort: 53,
                Protocol: Protocol.Udp,
                ProcessName: "stub.exe",
                ProcessId: 1234,
                BytesIn: rnd.Next(100, 10000),
                BytesOut: rnd.Next(100, 10000)
            );
            await Task.Delay(300, ct);
        }
    }
}
