using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Tests.Services;

public class ProcessIntegrityAnalyzerServiceTests
{
    private readonly ProcessIntegrityAnalyzerService _analyzer = new();

    [Theory]
    [InlineData("notepad.exe")]
    [InlineData("calc.exe")]
    [InlineData("mspaint.exe")]
    public async Task NoNetworkProcesses_FlagsOutboundConnection(string processName)
    {
        var alerts = await _analyzer.AnalyzeProcessAsync(processName, 0, "10.0.0.1", CancellationToken.None);

        Assert.Contains(alerts, a =>
            a.Type == AlertType.SuspiciousProcess &&
            a.Severity == RiskLevel.High &&
            a.Title.Contains("non-reseau"));
    }

    [Fact]
    public async Task LegitimateProcess_NoMasqueradeAlert()
    {
        // "chrome.exe" is not a system process name, should not trigger masquerade
        var alerts = await _analyzer.AnalyzeProcessAsync("chrome.exe", 0, "8.8.8.8", CancellationToken.None);

        Assert.DoesNotContain(alerts, a => a.Type == AlertType.ProcessMasquerade);
    }

    [Theory]
    [InlineData("svch0st.exe")]   // homoglyph: 0 instead of o
    [InlineData("svchostt.exe")]  // extra character (distance=1)
    public async Task Masquerading_DetectsNameSimilarToSystemProcess(string fakeName)
    {
        var alerts = await _analyzer.AnalyzeProcessAsync(fakeName, 0, "10.0.0.1", CancellationToken.None);

        Assert.Contains(alerts, a => a.Type == AlertType.ProcessMasquerade);
    }

    [Fact]
    public async Task DoubleExtension_DetectedAsMalicious()
    {
        var alerts = await _analyzer.AnalyzeProcessAsync("invoice.pdf.exe", 0, "10.0.0.1", CancellationToken.None);

        Assert.Contains(alerts, a =>
            a.Type == AlertType.ProcessMasquerade &&
            a.Title.Contains("Double extension"));
    }

    [Fact]
    public async Task NormalExecutable_NoDoubleExtensionAlert()
    {
        var alerts = await _analyzer.AnalyzeProcessAsync("firefox.exe", 0, "8.8.8.8", CancellationToken.None);

        Assert.DoesNotContain(alerts, a => a.Title.Contains("Double extension"));
    }

    [Fact]
    public void LevenshteinDistance_ExactMatch_ReturnsZero()
    {
        Assert.Equal(0, ProcessIntegrityAnalyzerService.LevenshteinDistance("svchost", "svchost"));
    }

    [Fact]
    public void LevenshteinDistance_OneCharDifference_ReturnsOne()
    {
        // "svchost" -> "svchst" is 1 deletion
        Assert.Equal(1, ProcessIntegrityAnalyzerService.LevenshteinDistance("svchst", "svchost"));
        // "scvhost" vs "svchost" is a transposition = 2 edits in Levenshtein
        Assert.Equal(2, ProcessIntegrityAnalyzerService.LevenshteinDistance("scvhost", "svchost"));
    }

    [Fact]
    public void LevenshteinDistance_EmptyStrings()
    {
        Assert.Equal(0, ProcessIntegrityAnalyzerService.LevenshteinDistance("", ""));
        Assert.Equal(5, ProcessIntegrityAnalyzerService.LevenshteinDistance("", "hello"));
        Assert.Equal(5, ProcessIntegrityAnalyzerService.LevenshteinDistance("hello", ""));
    }

    [Fact]
    public async Task CancelledToken_ThrowsOperationCancelled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<TaskCanceledException>(() =>
            _analyzer.AnalyzeProcessAsync("test.exe", 0, "10.0.0.1", cts.Token));
    }
}
