using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

public interface IGeoService
{
    Task<GeoInfo> LookupAsync(string ip, CancellationToken ct);
}
