using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

public interface IConnectionMonitor
{
    IAsyncEnumerable<Connection> GetLiveConnectionsAsync(CancellationToken ct);
}
