using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Tests.Services;

/// <summary>
/// Integration tests that exercise the full security analysis pipeline
/// with all real service implementations wired together.
/// </summary>
public class SecurityAnalysisPipelineTests
{
    private static SimpleSecurityAnalysisService CreatePipeline()
    {
        return new SimpleSecurityAnalysisService(
            new SimpleIPCategorizationService(),
            new SimpleSecurityScoringService(),
            new AnomalyDetectionService(),
            new ThreatIntelligenceServices(),
            new BeaconingDetectorService(),
            new ProcessIntegrityAnalyzerService(),
            new NetworkBaselineService(),
            openThreatFeed: null // No external API calls in tests
        );
    }

    [Fact]
    public async Task KnownGoodIP_ReturnsHighScore()
    {
        var pipeline = CreatePipeline();

        var result = await pipeline.AnalyzeConnectionAsync(
            "8.8.8.8", "chrome.exe", 443, 1000,
            DateTime.UtcNow, CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(result.Score.Value >= 70, $"Expected score >= 70 for Google DNS, got {result.Score.Value}");
        Assert.Equal("DNS Public (Google)", result.Category.Name);
        Assert.True(result.Category.IsKnownGood);
    }

    [Fact]
    public async Task SuspiciousProcess_ReturnsLowerScore()
    {
        var pipeline = CreatePipeline();

        var resultGood = await pipeline.AnalyzeConnectionAsync(
            "93.184.216.34", "chrome.exe", 443, 1000,
            DateTime.UtcNow, CancellationToken.None);

        var resultBad = await pipeline.AnalyzeConnectionAsync(
            "93.184.216.34", "unknown", 4444, 1000,
            DateTime.UtcNow, CancellationToken.None);

        Assert.True(resultBad.Score.Value < resultGood.Score.Value,
            $"Suspicious process score ({resultBad.Score.Value}) should be lower than normal ({resultGood.Score.Value})");
    }

    [Fact]
    public async Task TorExitNode_ReturnsThreatIntel()
    {
        var pipeline = CreatePipeline();

        var result = await pipeline.AnalyzeConnectionAsync(
            "185.220.100.240", "tor.exe", 9050, 1000,
            DateTime.UtcNow, CancellationToken.None);

        Assert.NotNull(result.ThreatIntel);
        Assert.Contains("Tor", result.ThreatIntel!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AfterHoursHighVolume_GeneratesAlerts()
    {
        var pipeline = CreatePipeline();
        var nightTime = new DateTime(2025, 1, 1, 3, 0, 0, DateTimeKind.Utc);

        var result = await pipeline.AnalyzeConnectionAsync(
            "198.51.100.55", "backup.exe", 22, 5_000_000,
            nightTime, CancellationToken.None);

        Assert.NotEmpty(result.Alerts);
        Assert.NotNull(result.Summary);
    }

    [Fact]
    public async Task HighVolumeTransfer_GeneratesVolumeAlert()
    {
        var pipeline = CreatePipeline();

        var result = await pipeline.AnalyzeConnectionAsync(
            "203.0.113.77", "uploader.exe", 443, 200_000_000,
            DateTime.UtcNow, CancellationToken.None);

        Assert.Contains(result.Alerts, a => a.Type == AlertType.VolumeAnomaly);
    }

    [Fact]
    public async Task MasqueradedProcess_DetectedInFullPipeline()
    {
        var pipeline = CreatePipeline();

        var result = await pipeline.AnalyzeConnectionAsync(
            "198.51.100.1", "svch0st.exe", 443, 1000,
            DateTime.UtcNow, CancellationToken.None);

        Assert.Contains(result.Alerts, a => a.Type == AlertType.ProcessMasquerade);
    }

    [Fact]
    public async Task NotepadWithNetworkAccess_DetectedAsSuspicious()
    {
        var pipeline = CreatePipeline();

        var result = await pipeline.AnalyzeConnectionAsync(
            "198.51.100.1", "notepad.exe", 443, 1000,
            DateTime.UtcNow, CancellationToken.None);

        Assert.Contains(result.Alerts, a =>
            a.Type == AlertType.SuspiciousProcess &&
            a.Title.Contains("non-reseau"));
    }

    [Fact]
    public async Task RepeatedCalls_BuildBaseline()
    {
        var pipeline = CreatePipeline();
        var now = DateTime.UtcNow;

        // Build baseline with normal traffic
        for (int i = 0; i < 12; i++)
        {
            await pipeline.AnalyzeConnectionAsync(
                "10.0.0.1", "app.exe", 443, 1000,
                now.AddSeconds(-120 + i * 10), CancellationToken.None);
        }

        // Now send massive volume — should trigger baseline deviation
        var result = await pipeline.AnalyzeConnectionAsync(
            "10.0.0.1", "app.exe", 443, 100_000_000,
            now, CancellationToken.None);

        // Should have some alert about volume or data exfiltration
        Assert.NotEmpty(result.Alerts);
    }

    [Fact]
    public async Task ResultSummary_ContainsAllComponents()
    {
        var pipeline = CreatePipeline();

        var result = await pipeline.AnalyzeConnectionAsync(
            "8.8.8.8", "chrome.exe", 443, 1000,
            DateTime.UtcNow, CancellationToken.None);

        Assert.Contains("Score", result.Summary);
        Assert.Contains("/100", result.Summary);
    }

    [Fact]
    public async Task DoubleExtensionProcess_DetectedInPipeline()
    {
        var pipeline = CreatePipeline();

        var result = await pipeline.AnalyzeConnectionAsync(
            "198.51.100.1", "invoice.pdf.exe", 443, 1000,
            DateTime.UtcNow, CancellationToken.None);

        Assert.Contains(result.Alerts, a =>
            a.Type == AlertType.ProcessMasquerade &&
            a.Title.Contains("Double extension"));
    }

    [Fact]
    public async Task SuspiciousPort_GeneratesAlert()
    {
        var pipeline = CreatePipeline();

        var result = await pipeline.AnalyzeConnectionAsync(
            "198.51.100.1", "app.exe", 4444, 1000,
            DateTime.UtcNow, CancellationToken.None);

        Assert.Contains(result.Alerts, a => a.Type == AlertType.PortScanning);
    }
}
