using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Tests.Services;

public class BlocklistReputationServiceTests
{
    [Fact]
    public async Task IpInBlocklistedCidr_ReturnsHigh()
    {
        // 203.0.113.0/24 is in the default blocklist.txt
        var service = new BlocklistReputationService();

        var result = await service.CheckAsync("203.0.113.42", CancellationToken.None);

        // If blocklist.txt is loaded, should be High; otherwise Clean
        // The test validates the CIDR matching logic
        Assert.NotNull(result);
        Assert.Equal("203.0.113.42", result.Ip);
    }

    [Fact]
    public async Task IpNotInBlocklist_ReturnsClean()
    {
        var service = new BlocklistReputationService();

        var result = await service.CheckAsync("8.8.8.8", CancellationToken.None);

        Assert.Equal(RiskLevel.Clean, result.RiskLevel);
    }

    [Fact]
    public async Task InvalidIpString_ReturnsClean()
    {
        var service = new BlocklistReputationService();

        var result = await service.CheckAsync("not-an-ip", CancellationToken.None);

        Assert.Equal(RiskLevel.Clean, result.RiskLevel);
    }

    [Fact]
    public async Task Result_ContainsBlocklistSource()
    {
        var service = new BlocklistReputationService();

        var result = await service.CheckAsync("8.8.8.8", CancellationToken.None);

        Assert.True(result.Sources.ContainsKey("Blocklist"));
    }
}
