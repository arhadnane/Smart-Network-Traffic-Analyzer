using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Tests.Services;

public class SimpleIPCategorizationServiceTests
{
    private readonly SimpleIPCategorizationService _service = new();

    [Theory]
    [InlineData("8.8.8.8", "DNS Public (Google)", true)]
    [InlineData("1.1.1.1", "DNS Public (Cloudflare)", true)]
    [InlineData("208.67.222.222", "DNS Public (OpenDNS)", true)]
    [InlineData("4.2.2.2", "DNS Public (Level3)", false)]
    public async Task ExactMatch_ReturnsCorrectCategory(string ip, string expectedName, bool isKnownGood)
    {
        var result = await _service.CategorizeAsync(ip, CancellationToken.None);

        Assert.Equal(expectedName, result.Name);
        Assert.Equal(RiskLevel.Clean, result.Risk);
        Assert.Equal(isKnownGood, result.IsKnownGood);
    }

    [Theory]
    [InlineData("172.217.14.78", "Google Frontend")]
    [InlineData("216.58.213.110", "Google Frontend")]
    [InlineData("151.101.1.69", "Fastly CDN")]
    [InlineData("199.232.36.132", "Fastly CDN")]
    [InlineData("157.240.1.35", "Facebook / Meta")]
    [InlineData("31.13.65.36", "Facebook / Meta")]
    public async Task PrefixMatch_ReturnsCorrectCategory(string ip, string expectedName)
    {
        var result = await _service.CategorizeAsync(ip, CancellationToken.None);

        Assert.Equal(expectedName, result.Name);
    }

    [Theory]
    [InlineData("13.107.42.14", "Amazon AWS")]
    [InlineData("52.84.150.1", "Amazon AWS")]
    [InlineData("40.90.4.2", "Microsoft Azure")]
    [InlineData("20.42.0.1", "Microsoft Azure")]
    public async Task CloudProvider_ReturnsLowRisk(string ip, string expectedName)
    {
        var result = await _service.CategorizeAsync(ip, CancellationToken.None);

        Assert.Equal(expectedName, result.Name);
        Assert.Equal(RiskLevel.Low, result.Risk);
    }

    [Fact]
    public async Task UnknownIp_ReturnsServiceInconnu()
    {
        var result = await _service.CategorizeAsync("93.184.216.34", CancellationToken.None);

        Assert.Equal("Service Inconnu", result.Name);
        Assert.Equal(RiskLevel.Medium, result.Risk);
    }

    [Fact]
    public async Task EmptyIp_ReturnsInconnu()
    {
        var result = await _service.CategorizeAsync("", CancellationToken.None);

        Assert.Equal("Inconnu", result.Name);
    }

    [Fact]
    public async Task NullIp_ReturnsInconnu()
    {
        var result = await _service.CategorizeAsync(null!, CancellationToken.None);

        Assert.Equal("Inconnu", result.Name);
    }

    [Fact]
    public async Task CancelledToken_ThrowsOperationCancelled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<TaskCanceledException>(() =>
            _service.CategorizeAsync("8.8.8.8", cts.Token));
    }
}
