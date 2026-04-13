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

public class SimpleSecurityScoringServiceTests
{
    private readonly SimpleSecurityScoringService _service = new();

    [Fact]
    public async Task KnownGoodCategory_HighScore()
    {
        var category = new IPCategory("Google DNS", "Test", RiskLevel.Clean, IsKnownGood: true);
        var context = new SecurityScoringContext("8.8.8.8", "chrome.exe", 443, 1000);

        var score = await _service.CalculateScoreAsync(context, category, Array.Empty<SecurityAlert>(), CancellationToken.None);

        Assert.True(score.Value >= 80);
        Assert.True(score.Level is RiskLevel.Clean or RiskLevel.Low);
        Assert.True(score.FactorScores.ContainsKey("Services de confiance"));
    }

    [Fact]
    public async Task KnownBadCategory_LowScore()
    {
        var category = new IPCategory("Malware", "Test", RiskLevel.High, IsKnownBad: true);
        var context = new SecurityScoringContext("198.51.100.1", "unknown.exe", 4444, 100_000_000);

        var score = await _service.CalculateScoreAsync(context, category, Array.Empty<SecurityAlert>(), CancellationToken.None);

        Assert.True(score.Value < 30);
        Assert.True(score.Level is RiskLevel.High or RiskLevel.Malicious);
    }

    [Fact]
    public async Task NonStandardPort_LowersScore()
    {
        var category = new IPCategory("Unknown", "Test", RiskLevel.Medium);
        var contextStandard = new SecurityScoringContext("10.0.0.1", "app.exe", 443, 1000);
        var contextNonStandard = new SecurityScoringContext("10.0.0.1", "app.exe", 4444, 1000);

        var scoreStandard = await _service.CalculateScoreAsync(contextStandard, category, Array.Empty<SecurityAlert>(), CancellationToken.None);
        var scoreNonStandard = await _service.CalculateScoreAsync(contextNonStandard, category, Array.Empty<SecurityAlert>(), CancellationToken.None);

        Assert.True(scoreNonStandard.Value < scoreStandard.Value);
    }

    [Theory]
    [InlineData(80, true)]   // standard
    [InlineData(443, true)]  // standard
    [InlineData(53, true)]   // standard
    [InlineData(22, true)]   // standard
    [InlineData(8080, false)] // non-standard
    [InlineData(4444, false)] // non-standard
    public async Task PortStandards_AffectsScore(int port, bool isStandard)
    {
        var category = new IPCategory("Test", "Test", RiskLevel.Medium);
        var context = new SecurityScoringContext("10.0.0.1", "app.exe", port, 1000);

        var score = await _service.CalculateScoreAsync(context, category, Array.Empty<SecurityAlert>(), CancellationToken.None);

        if (isStandard)
            Assert.DoesNotContain("Port non standard", score.FactorScores.Keys);
        else
            Assert.Contains("Port non standard", score.FactorScores.Keys);
    }

    [Fact]
    public async Task SuspiciousProcessName_LowersScore()
    {
        var category = new IPCategory("Unknown", "Test", RiskLevel.Medium);
        var contextNormal = new SecurityScoringContext("10.0.0.1", "chrome.exe", 443, 1000);
        var contextSuspect = new SecurityScoringContext("10.0.0.1", "unknown", 443, 1000);

        var scoreNormal = await _service.CalculateScoreAsync(contextNormal, category, Array.Empty<SecurityAlert>(), CancellationToken.None);
        var scoreSuspect = await _service.CalculateScoreAsync(contextSuspect, category, Array.Empty<SecurityAlert>(), CancellationToken.None);

        Assert.True(scoreSuspect.Value < scoreNormal.Value);
        Assert.Contains("Processus suspect", scoreSuspect.FactorScores.Keys);
    }

    [Fact]
    public async Task HighVolumeTransfer_LowersScore()
    {
        var category = new IPCategory("Unknown", "Test", RiskLevel.Medium);
        var contextLow = new SecurityScoringContext("10.0.0.1", "app.exe", 443, 1_000);
        var contextHigh = new SecurityScoringContext("10.0.0.1", "app.exe", 443, 200_000_000);

        var scoreLow = await _service.CalculateScoreAsync(contextLow, category, Array.Empty<SecurityAlert>(), CancellationToken.None);
        var scoreHigh = await _service.CalculateScoreAsync(contextHigh, category, Array.Empty<SecurityAlert>(), CancellationToken.None);

        Assert.True(scoreHigh.Value < scoreLow.Value);
    }

    [Fact]
    public async Task MultipleAlerts_AccumulatePenalties()
    {
        var category = new IPCategory("Unknown", "Test", RiskLevel.Medium);
        var context = new SecurityScoringContext("10.0.0.1", "app.exe", 443, 1000);

        var alerts = new SecurityAlert[]
        {
            new(AlertType.VolumeAnomaly, RiskLevel.High, "Test1", "Desc1", DateTime.UtcNow),
            new(AlertType.SuspiciousProcess, RiskLevel.Medium, "Test2", "Desc2", DateTime.UtcNow),
            new(AlertType.Beaconing, RiskLevel.High, "Test3", "Desc3", DateTime.UtcNow),
        };

        var scoreNoAlerts = await _service.CalculateScoreAsync(context, category, Array.Empty<SecurityAlert>(), CancellationToken.None);
        var scoreWithAlerts = await _service.CalculateScoreAsync(context, category, alerts, CancellationToken.None);

        Assert.True(scoreWithAlerts.Value < scoreNoAlerts.Value);
        Assert.Contains("Alertes securite", scoreWithAlerts.FactorScores.Keys);
    }

    [Fact]
    public async Task ScoreClampedBetween0And100()
    {
        // Worst case: known bad + suspicious process + non-standard port + high volume + many alerts
        var category = new IPCategory("Malware", "Test", RiskLevel.Malicious, IsKnownBad: true);
        var context = new SecurityScoringContext("10.0.0.1", "unknown", 4444, 500_000_000);
        var alerts = Enumerable.Range(0, 10)
            .Select(i => new SecurityAlert(AlertType.MalwareIP, RiskLevel.Malicious, $"Alert{i}", $"Desc{i}", DateTime.UtcNow))
            .ToArray();

        var score = await _service.CalculateScoreAsync(context, category, alerts, CancellationToken.None);

        Assert.InRange(score.Value, 0, 100);
    }

    [Fact]
    public async Task CancelledToken_ThrowsOperationCancelled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var category = new IPCategory("Test", "Test", RiskLevel.Medium);
        var context = new SecurityScoringContext("10.0.0.1", "app.exe", 443, 1000);

        await Assert.ThrowsAsync<TaskCanceledException>(() =>
            _service.CalculateScoreAsync(context, category, Array.Empty<SecurityAlert>(), cts.Token));
    }
}
