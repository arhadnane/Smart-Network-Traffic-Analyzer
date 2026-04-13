using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Provides IP geolocation lookups.
/// </summary>
public interface IGeoService
{
    Task<GeoInfo> LookupAsync(string ip, CancellationToken ct);
}