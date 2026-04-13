using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Tests.Services;

public class ThreatIntelligenceServicesTests
{
    [Fact]
    public async Task LookupAsync_ReturnsCidrIndicatorDescription()
    {
        var service = new ThreatIntelligenceServices();

        var result = await service.LookupAsync("185.220.100.42", CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains("Tor exit cluster", result!);
    }

    [Fact]
    public async Task LookupAsync_CachesResultsForRepeatedQueries()
    {
        var service = new ThreatIntelligenceServices();
        var cacheField = typeof(ThreatIntelligenceServices)
            .GetField("_cache", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var cacheInstance = cacheField.GetValue(service)!;
        var countProperty = cacheInstance.GetType().GetProperty("Count")!;

        var ip = "203.0.113.5"; // bogon prefix triggers message + cache

        Assert.Equal(0, (int)countProperty.GetValue(cacheInstance)!);

        await service.LookupAsync(ip, CancellationToken.None);
        var countAfterFirst = (int)countProperty.GetValue(cacheInstance)!;

        await service.LookupAsync(ip, CancellationToken.None);
        var countAfterSecond = (int)countProperty.GetValue(cacheInstance)!;

        Assert.Equal(1, countAfterFirst);
        Assert.Equal(countAfterFirst, countAfterSecond); // hit the cached entry instead of adding another
    }
}
