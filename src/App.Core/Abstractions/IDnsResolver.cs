namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

public interface IDnsResolver
{
    Task<string?> ReverseLookupAsync(string ip, CancellationToken ct);
}
