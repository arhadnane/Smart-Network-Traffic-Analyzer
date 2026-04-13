using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Tests.Services;

public class AggregatedReputationServiceTests
{
    private sealed class FakeReputationService : IReputationService
    {
        private readonly RiskLevel _level;
        private readonly string _sourceName;

        public FakeReputationService(RiskLevel level, string sourceName = "FakeSource")
        {
            _level = level;
            _sourceName = sourceName;
        }

        public Task<Reputation> CheckAsync(string ip, CancellationToken ct)
        {
            var sources = new Dictionary<string, string> { { _sourceName, _level.ToString() } };
            return Task.FromResult(new Reputation(ip, _level, sources, DateTimeOffset.UtcNow));
        }
    }

    private sealed class ThrowingReputationService : IReputationService
    {
        public Task<Reputation> CheckAsync(string ip, CancellationToken ct)
            => throw new InvalidOperationException("Provider failed");
    }

    [Fact]
    public async Task SingleProvider_ReturnsProviderResult()
    {
        var service = new AggregatedReputationService(new[]
        {
            new FakeReputationService(RiskLevel.Medium, "TestSource")
        });

        var result = await service.CheckAsync("10.0.0.1", CancellationToken.None);

        Assert.Equal(RiskLevel.Medium, result.RiskLevel);
        Assert.Single(result.Sources);
    }

    [Fact]
    public async Task MultipleProviders_ReturnsHighestRisk()
    {
        var service = new AggregatedReputationService(new[]
        {
            new FakeReputationService(RiskLevel.Clean, "SourceA"),
            new FakeReputationService(RiskLevel.High, "SourceB"),
            new FakeReputationService(RiskLevel.Low, "SourceC"),
        });

        var result = await service.CheckAsync("10.0.0.1", CancellationToken.None);

        Assert.Equal(RiskLevel.High, result.RiskLevel);
        Assert.Equal(3, result.Sources.Count);
    }

    [Fact]
    public async Task ProviderThrows_OtherProvidersStillQueried()
    {
        var service = new AggregatedReputationService(new IReputationService[]
        {
            new ThrowingReputationService(),
            new FakeReputationService(RiskLevel.Medium, "GoodSource"),
        });

        var result = await service.CheckAsync("10.0.0.1", CancellationToken.None);

        Assert.Equal(RiskLevel.Medium, result.RiskLevel);
        Assert.Single(result.Sources);
    }

    [Fact]
    public async Task NoProviders_ReturnsClean()
    {
        var service = new AggregatedReputationService(Array.Empty<IReputationService>());

        var result = await service.CheckAsync("10.0.0.1", CancellationToken.None);

        Assert.Equal(RiskLevel.Clean, result.RiskLevel);
        Assert.Empty(result.Sources);
    }

    [Fact]
    public async Task AllProvidersFail_ReturnsClean()
    {
        var service = new AggregatedReputationService(new IReputationService[]
        {
            new ThrowingReputationService(),
            new ThrowingReputationService(),
        });

        var result = await service.CheckAsync("10.0.0.1", CancellationToken.None);

        Assert.Equal(RiskLevel.Clean, result.RiskLevel);
    }
}
