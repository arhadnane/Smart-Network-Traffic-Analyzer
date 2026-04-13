using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Tests.Services;

public class NetworkBaselineServiceTests
{
    [Fact]
    public async Task BelowMinSamples_NoAlerts()
    {
        var service = new NetworkBaselineService();
        var now = DateTime.UtcNow;

        // Record only 5 samples (below MinSamplesForBaseline = 10)
        for (int i = 0; i < 5; i++)
        {
            service.RecordSample("app.exe", "10.0.0.1", 443, 1000, now.AddSeconds(-i * 10));
        }

        var alerts = await service.EvaluateAsync("app.exe", "10.0.0.1", 443, 1000, now, CancellationToken.None);
        Assert.Empty(alerts);
    }

    [Fact]
    public async Task VolumeAnomaly_DetectedWhenFarAboveBaseline()
    {
        var service = new NetworkBaselineService();
        var now = DateTime.UtcNow;

        // Build baseline: 15 samples of ~1KB
        for (int i = 0; i < 15; i++)
        {
            service.RecordSample("app.exe", "10.0.0.1", 443, 1_000, now.AddSeconds(-120 + i * 5));
        }

        // Now send 50MB — way above baseline (4x threshold)
        var alerts = await service.EvaluateAsync("app.exe", "10.0.0.1", 443, 50_000_000, now, CancellationToken.None);

        Assert.Contains(alerts, a => a.Type == AlertType.DataExfiltration);
    }

    [Fact]
    public async Task NormalVolume_NoExfiltrationAlert()
    {
        var service = new NetworkBaselineService();
        var now = DateTime.UtcNow;

        // Build baseline: 15 samples of ~1MB
        for (int i = 0; i < 15; i++)
        {
            service.RecordSample("app.exe", "10.0.0.1", 443, 1_000_000, now.AddSeconds(-120 + i * 5));
        }

        // Send 2MB — within normal range (< 4x of 1MB average)
        var alerts = await service.EvaluateAsync("app.exe", "10.0.0.1", 443, 2_000_000, now, CancellationToken.None);

        Assert.DoesNotContain(alerts, a => a.Type == AlertType.DataExfiltration);
    }

    [Fact]
    public async Task UnusualPort_DetectedWhenProcessHasEstablishedPattern()
    {
        var service = new NetworkBaselineService();
        var now = DateTime.UtcNow;

        // Build baseline: process normally uses ports 80, 443, 8080
        for (int i = 0; i < 15; i++)
        {
            var port = i % 3 switch { 0 => 80, 1 => 443, _ => 8080 };
            service.RecordSample("app.exe", "10.0.0.1", port, 1000, now.AddSeconds(-120 + i * 5));
        }

        // Now use port 4444 (unusual for this process)
        var alerts = await service.EvaluateAsync("app.exe", "10.0.0.1", 4444, 1000, now, CancellationToken.None);

        Assert.Contains(alerts, a =>
            a.Type == AlertType.AbnormalTrafficPattern &&
            a.Title.Contains("Port inhabituel"));
    }

    [Fact]
    public async Task DestinationDiversitySpike_DetectedWhenManyNewIPs()
    {
        var service = new NetworkBaselineService();
        var now = DateTime.UtcNow;

        // Build baseline with steady single-IP traffic
        for (int i = 0; i < 15; i++)
        {
            service.RecordSample("scanner.exe", "10.0.0.1", 443, 1000, now.AddSeconds(-120 + i * 5));
        }

        // Now suddenly contact 15 new IPs in the last minute
        for (int i = 0; i < 15; i++)
        {
            service.RecordSample("scanner.exe", $"192.168.1.{i + 10}", 443, 1000, now.AddSeconds(-30 + i));
        }

        var alerts = await service.EvaluateAsync("scanner.exe", "192.168.1.30", 443, 1000, now, CancellationToken.None);

        Assert.Contains(alerts, a =>
            a.Type == AlertType.AbnormalTrafficPattern &&
            a.Title.Contains("Diversification"));
    }

    [Fact]
    public async Task FrequencyAnomaly_DetectedWhenRateSpikeAboveBaseline()
    {
        var service = new NetworkBaselineService();
        var now = DateTime.UtcNow;

        // Build a low-rate baseline spread over a longer window
        // 12 samples over 10 minutes = ~1.2/min average
        for (int i = 0; i < 12; i++)
        {
            service.RecordSample("app.exe", "10.0.0.1", 443, 1000, now.AddMinutes(-10).AddSeconds(i * 50));
        }

        // Now burst: 40 connections in the last 30 seconds
        // This pushes connections-in-last-minute well above 3x the average
        for (int i = 0; i < 40; i++)
        {
            service.RecordSample("app.exe", "10.0.0.1", 443, 1000, now.AddSeconds(-29 + i * 0.5));
        }

        var alerts = await service.EvaluateAsync("app.exe", "10.0.0.1", 443, 1000, now, CancellationToken.None);

        Assert.Contains(alerts, a =>
            a.Type == AlertType.AbnormalTrafficPattern &&
            a.Title.Contains("Frequence"));
    }

    [Fact]
    public async Task UnknownProcess_NoAlertsWithoutBaseline()
    {
        var service = new NetworkBaselineService();
        var now = DateTime.UtcNow;

        // No baseline for "newapp.exe" — should return empty
        var alerts = await service.EvaluateAsync("newapp.exe", "10.0.0.1", 443, 1000, now, CancellationToken.None);
        Assert.Empty(alerts);
    }
}
