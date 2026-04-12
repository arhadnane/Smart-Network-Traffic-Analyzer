using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Monitors live network connections and yields them as a stream.
/// </summary>
public interface IConnectionMonitor
{
    IAsyncEnumerable<Connection> GetLiveConnectionsAsync(CancellationToken ct);
}