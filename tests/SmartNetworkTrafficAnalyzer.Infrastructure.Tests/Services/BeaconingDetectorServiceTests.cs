using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Tests.Services;

public class BeaconingDetectorServiceTests
{
    [Fact]
    public async Task RegularIntervalConnections_DetectsBeaconing()
    {
        var detector = new BeaconingDetectorService();
        var baseTime = DateTime.UtcNow.AddMinutes(-10);
        const string ip = "198.51.100.10";
        const string process = "malware.exe";

        // Simulate connections every 60 seconds (very regular = C2 beacon)
        for (int i = 0; i < 8; i++)
        {
            detector.RecordConnection(ip, process, baseTime.AddSeconds(i * 60));
        }

        var alerts = await detector.DetectBeaconingAsync(ip, CancellationToken.None);

        Assert.NotEmpty(alerts);
        Assert.Contains(alerts, a => a.Type == AlertType.Beaconing);
    }

    [Fact]
    public async Task IrregularConnections_NoBeaconingAlert()
    {
        var detector = new BeaconingDetectorService();
        var baseTime = DateTime.UtcNow.AddMinutes(-10);
        const string ip = "198.51.100.20";
        const string process = "browser.exe";

        // Random-ish intervals — not a beacon pattern
        var offsets = new[] { 0, 5, 45, 50, 120, 180, 185, 300 };
        foreach (var offset in offsets)
        {
            detector.RecordConnection(ip, process, baseTime.AddSeconds(offset));
        }

        var alerts = await detector.DetectBeaconingAsync(ip, CancellationToken.None);

        // Should not have high-severity beaconing (CV too high)
        Assert.DoesNotContain(alerts, a => a.Type == AlertType.Beaconing && a.Severity == RiskLevel.High);
    }

    [Fact]
    public async Task TooFewSamples_NoAlerts()
    {
        var detector = new BeaconingDetectorService();
        var baseTime = DateTime.UtcNow.AddMinutes(-5);
        const string ip = "198.51.100.30";

        // Only 3 connections — below MinSamplesForDetection (5)
        for (int i = 0; i < 3; i++)
        {
            detector.RecordConnection(ip, "app.exe", baseTime.AddSeconds(i * 60));
        }

        var alerts = await detector.DetectBeaconingAsync(ip, CancellationToken.None);
        Assert.Empty(alerts);
    }

    [Fact]
    public async Task JitteredBeacon_DetectsWithLowerSeverity()
    {
        var detector = new BeaconingDetectorService();
        var baseTime = DateTime.UtcNow.AddMinutes(-15);
        const string ip = "198.51.100.40";
        var rng = new Random(42);

        // 10 connections ~every 30 seconds with +/-5s jitter
        for (int i = 0; i < 10; i++)
        {
            var jitter = rng.Next(-5, 6);
            detector.RecordConnection(ip, "beacon.exe", baseTime.AddSeconds(i * 30 + jitter));
        }

        var alerts = await detector.DetectBeaconingAsync(ip, CancellationToken.None);

        Assert.NotEmpty(alerts);
        Assert.Contains(alerts, a => a.Type == AlertType.Beaconing);
    }

    [Fact]
    public async Task DifferentProcesses_AnalyzedSeparately()
    {
        var detector = new BeaconingDetectorService();
        var baseTime = DateTime.UtcNow.AddMinutes(-10);
        const string ip = "198.51.100.50";

        // Process A: regular beaconing
        for (int i = 0; i < 8; i++)
            detector.RecordConnection(ip, "malware.exe", baseTime.AddSeconds(i * 30));

        // Process B: irregular (only 2 connections)
        detector.RecordConnection(ip, "browser.exe", baseTime);
        detector.RecordConnection(ip, "browser.exe", baseTime.AddSeconds(120));

        var alerts = await detector.DetectBeaconingAsync(ip, CancellationToken.None);

        // Should detect beaconing only for malware.exe
        Assert.Contains(alerts, a => a.Type == AlertType.Beaconing && a.RelatedProcess == "malware.exe");
        Assert.DoesNotContain(alerts, a => a.RelatedProcess == "browser.exe");
    }
}
