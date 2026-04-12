using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Tests.Services;

public class BlocklistReputationServiceTests
{
    private readonly ILoggingService _logger = new ConsoleLoggingService();

    [Fact]
    public async Task CheckAsync_PublicIPNotInBlocklist_ReturnsClean()
    {
        var service = new BlocklistReputationService(_logger, "/nonexistent/blocklist.txt");
        var result = await service.CheckAsync("8.8.8.8", CancellationToken.None);
        Assert.Equal(RiskLevel.Clean, result.RiskLevel);
    }

    [Fact]
    public async Task CheckAsync_InvalidIP_ReturnsClean()
    {
        var service = new BlocklistReputationService(_logger, "/nonexistent/blocklist.txt");
        var result = await service.CheckAsync("invalid-ip", CancellationToken.None);
        Assert.Equal(RiskLevel.Clean, result.RiskLevel);
    }

    [Fact]
    public async Task CheckAsync_NullOrEmptyIP_Throws()
    {
        var service = new BlocklistReputationService(_logger, "/nonexistent/blocklist.txt");
        await Assert.ThrowsAsync<ArgumentException>(() => service.CheckAsync("", CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => service.CheckAsync(null!, CancellationToken.None));
    }

    [Fact]
    public async Task CheckAsync_ValidResult_ContainsSources()
    {
        var service = new BlocklistReputationService(_logger, "/nonexistent/blocklist.txt");
        var result = await service.CheckAsync("1.2.3.4", CancellationToken.None);
        Assert.NotEmpty(result.Sources);
        Assert.True(result.Sources.ContainsKey("Blocklist"));
    }
}

public class AggregatedReputationServiceTests
{
    private readonly ILoggingService _logger = new ConsoleLoggingService();

    [Fact]
    public async Task CheckAsync_NoProviders_ReturnsClean()
    {
        var service = new AggregatedReputationService(Enumerable.Empty<IReputationService>(), _logger);
        var result = await service.CheckAsync("8.8.8.8", CancellationToken.None);
        Assert.Equal(RiskLevel.Clean, result.RiskLevel);
    }

    [Fact]
    public async Task CheckAsync_MultipleProviders_ReturnsHighestRisk()
    {
        var providers = new IReputationService[]
        {
            new StubReputationService(),
        };
        var service = new AggregatedReputationService(providers, _logger);
        var result = await service.CheckAsync("8.8.8.5", CancellationToken.None);
        Assert.Equal(RiskLevel.Medium, result.RiskLevel);
    }

    [Fact]
    public async Task CheckAsync_ProviderThrows_ContinuesWithOthers()
    {
        var throwingProvider = new ThrowingReputationService();
        var workingProvider = new StubReputationService();
        var service = new AggregatedReputationService(new[] { throwingProvider, workingProvider }, _logger);
        var result = await service.CheckAsync("1.1.1.1", CancellationToken.None);
        // Should still get a result from the working provider
        Assert.NotEqual(DateTimeOffset.MinValue, result.LastChecked);
    }

    private class ThrowingReputationService : IReputationService
    {
        public Task<Reputation> CheckAsync(string ip, CancellationToken ct)
            => throw new InvalidOperationException("Test failure");
    }
}

public class StubServicesTests
{
    [Fact]
    public async Task StubDnsResolver_KnownIP_ReturnsHostname()
    {
        var resolver = new StubDnsResolver();
        var result = await resolver.ReverseLookupAsync("8.8.8.1", CancellationToken.None);
        Assert.Equal("dns.google", result);
    }

    [Fact]
    public async Task StubDnsResolver_UnknownIP_ReturnsNull()
    {
        var resolver = new StubDnsResolver();
        var result = await resolver.ReverseLookupAsync("10.0.0.1", CancellationToken.None);
        Assert.Null(result);
    }

    [Fact]
    public async Task StubGeoService_GoogleIP_ReturnsUS()
    {
        var geo = new StubGeoService();
        var result = await geo.LookupAsync("8.8.8.8", CancellationToken.None);
        Assert.Equal("US", result.Country);
    }

    [Fact]
    public async Task StubGeoService_CloudflareIP_ReturnsProvider()
    {
        var geo = new StubGeoService();
        var result = await geo.LookupAsync("1.1.1.1", CancellationToken.None);
        Assert.Equal("Cloudflare", result.Provider);
        Assert.Equal("AS13335", result.Asn);
    }

    [Fact]
    public async Task StubReputationService_CloudflareIP_ReturnsLow()
    {
        var rep = new StubReputationService();
        var result = await rep.CheckAsync("1.1.1.1", CancellationToken.None);
        Assert.Equal(RiskLevel.Low, result.RiskLevel);
    }

    [Fact]
    public async Task StubReputationService_GoogleIP_ReturnsMedium()
    {
        var rep = new StubReputationService();
        var result = await rep.CheckAsync("8.8.8.5", CancellationToken.None);
        Assert.Equal(RiskLevel.Medium, result.RiskLevel);
    }
}

public class InMemorySettingsServiceTests
{
    [Fact]
    public void Get_MissingKey_ReturnsDefault()
    {
        var settings = new InMemorySettingsService();
        var result = settings.Get("missing", 42);
        Assert.Equal(42, result);
    }

    [Fact]
    public void Set_And_Get_RoundTrip()
    {
        var settings = new InMemorySettingsService();
        settings.Set("key1", "hello");
        Assert.Equal("hello", settings.Get("key1", "default"));
    }

    [Fact]
    public void Set_Overwrites_ExistingValue()
    {
        var settings = new InMemorySettingsService();
        settings.Set("key1", "first");
        settings.Set("key1", "second");
        Assert.Equal("second", settings.Get("key1", "default"));
    }

    [Fact]
    public void Get_WrongType_ReturnsDefault()
    {
        var settings = new InMemorySettingsService();
        settings.Set("key1", "string value");
        var result = settings.Get("key1", 0);
        Assert.Equal(0, result);
    }

    [Fact]
    public void Set_NullOrEmptyKey_Throws()
    {
        var settings = new InMemorySettingsService();
        Assert.Throws<ArgumentException>(() => settings.Set("", "value"));
        Assert.Throws<ArgumentException>(() => settings.Set(null!, "value"));
    }
}

public class SimpleIPCategorizationServiceTests
{
    private readonly SimpleIPCategorizationService _service = new();

    [Fact]
    public async Task CategorizeAsync_ExactMatch_GoogleDNS()
    {
        var result = await _service.CategorizeAsync("8.8.8.8");
        Assert.True(result.IsKnownGood);
        Assert.Contains("DNS", result.Name);
    }

    [Fact]
    public async Task CategorizeAsync_PrefixMatch_GoogleServices()
    {
        var result = await _service.CategorizeAsync("8.8.4.4");
        Assert.Equal("Google Services", result.Name);
    }

    [Fact]
    public async Task CategorizeAsync_PrefixMatch_AmazonAWS()
    {
        var result = await _service.CategorizeAsync("13.57.21.100");
        Assert.Equal("Amazon AWS", result.Name);
        Assert.True(result.IsKnownGood);
    }

    [Fact]
    public async Task CategorizeAsync_PrefixMatch_TorNodes()
    {
        var result = await _service.CategorizeAsync("185.220.101.1");
        Assert.Equal("Tor Exit Nodes", result.Name);
        Assert.False(result.IsKnownGood);
    }

    [Fact]
    public async Task CategorizeAsync_UnknownIP_ReturnsUnknown()
    {
        var result = await _service.CategorizeAsync("203.0.113.50");
        Assert.Equal("Unknown", result.Name);
        Assert.Equal(RiskLevel.Clean, result.Risk);
    }

    [Fact]
    public async Task CategorizeAsync_NullOrEmptyIP_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _service.CategorizeAsync(""));
        await Assert.ThrowsAsync<ArgumentException>(() => _service.CategorizeAsync(null!));
    }
}

public class SimpleSecurityScoringServiceTests
{
    private readonly SimpleSecurityScoringService _service = new();

    [Fact]
    public async Task CalculateScoreAsync_KnownGoodService_HighScore()
    {
        var category = new IPCategory("Google Services", "Known CDN", RiskLevel.Low, IsKnownGood: true);
        var score = await _service.CalculateScoreAsync("8.8.8.8", category, Array.Empty<SecurityAlert>());
        Assert.True(score.Value >= 80);
    }

    [Fact]
    public async Task CalculateScoreAsync_UnknownService_MidScore()
    {
        var category = new IPCategory("Unknown", "No info", RiskLevel.Clean);
        var score = await _service.CalculateScoreAsync("1.2.3.4", category, Array.Empty<SecurityAlert>());
        Assert.Equal(50, score.Value);
    }

    [Fact]
    public async Task CalculateScoreAsync_WithAlerts_LowerScore()
    {
        var category = new IPCategory("Unknown", "No info", RiskLevel.Clean);
        var alerts = new[]
        {
            new SecurityAlert(AlertType.VolumeAnomaly, RiskLevel.High, "Vol", "High", DateTime.UtcNow)
        };
        var score = await _service.CalculateScoreAsync("1.2.3.4", category, alerts);
        Assert.True(score.Value < 50);
    }
}

public class SimpleAnomalyDetectionServiceTests
{
    private readonly SimpleAnomalyDetectionService _service = new(new ConsoleLoggingService());

    [Fact]
    public async Task CheckAnomaliesAsync_HighVolume_ReturnsAlert()
    {
        var alerts = await _service.CheckAnomaliesAsync("1.2.3.4", "test", 200_000_000, DateTime.UtcNow);
        Assert.NotEmpty(alerts);
        Assert.Contains(alerts, a => a.Type == AlertType.VolumeAnomaly && a.Severity == RiskLevel.High);
    }

    [Fact]
    public async Task CheckAnomaliesAsync_NormalVolume_NoAlert()
    {
        var alerts = await _service.CheckAnomaliesAsync("1.2.3.4", "chrome", 5000, DateTime.UtcNow);
        Assert.Empty(alerts);
    }

    [Fact]
    public async Task CheckAnomaliesAsync_SuspiciousProcess_ReturnsAlert()
    {
        var alerts = await _service.CheckAnomaliesAsync("1.2.3.4", "unknown_temp.exe", 100, DateTime.UtcNow);
        Assert.Contains(alerts, a => a.Type == AlertType.SuspiciousProcess);
    }
}

public class ThreatIntelligenceServiceTests
{
    private readonly ThreatIntelligenceService _service = new();

    [Fact]
    public async Task GetThreatIntelligenceAsync_KnownBadIP_ReturnsThreat()
    {
        var result = await _service.GetThreatIntelligenceAsync("185.220.100.240");
        Assert.NotNull(result);
        Assert.Contains("Tor", result);
    }

    [Fact]
    public async Task GetThreatIntelligenceAsync_SuspiciousRange_ReturnsThreat()
    {
        var result = await _service.GetThreatIntelligenceAsync("185.220.101.1");
        Assert.NotNull(result);
        Assert.Contains("Tor", result);
    }

    [Fact]
    public async Task GetThreatIntelligenceAsync_CleanIP_ReturnsNull()
    {
        var result = await _service.GetThreatIntelligenceAsync("8.8.8.8");
        Assert.Null(result);
    }

    [Fact]
    public async Task GetThreatIntelligenceAsync_NullOrEmptyIP_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _service.GetThreatIntelligenceAsync(""));
        await Assert.ThrowsAsync<ArgumentException>(() => _service.GetThreatIntelligenceAsync(null!));
    }
}