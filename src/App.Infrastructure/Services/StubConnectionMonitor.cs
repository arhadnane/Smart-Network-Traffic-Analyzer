using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Stub connection monitor that yields fake connections for testing.
/// </summary>
public sealed class StubConnectionMonitor : IConnectionMonitor
{
    private readonly ILoggingService _logger;

    public StubConnectionMonitor(ILoggingService logger)
    {
        _logger = logger;
    }

    public async IAsyncEnumerable<Connection> GetLiveConnectionsAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        _logger.Warn("Using STUB connection data — not real connections!");
        var rnd = new Random();
        var start = DateTimeOffset.UtcNow;

        for (int i = 1; i <= 10 && !ct.IsCancellationRequested; i++)
        {
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