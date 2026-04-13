using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Tests.Services;

public class AnomalyDetectionServiceTests
{
    [Fact]
    public async Task BurstTrafficProducesRapidConnectionsAlert()
    {
        var service = new AnomalyDetectionService();
        var now = new DateTime(2025, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        const string ip = "203.0.113.5";
        const string process = "browser.exe";
        const int port = 443;

        for (var i = 0; i < 20; i++)
        {
            service.RecordConnection(ip, process, port, 1024, now.AddSeconds(-i));
        }

        var alerts = await service.CheckAnomaliesAsync(ip, process, port, 4_096, now, CancellationToken.None);

        Assert.Contains(alerts, a => a.Type == AlertType.RapidConnections && a.Severity == RiskLevel.High);
    }

    [Fact]
    public async Task AfterHoursLargeTransferTriggersUnknownDestinationAlert()
    {
        var service = new AnomalyDetectionService();
        var night = new DateTime(2025, 1, 1, 2, 0, 0, DateTimeKind.Utc);

        var alerts = await service.CheckAnomaliesAsync(
            "198.51.100.77",
            "backup.exe",
            22,
            2_500_000,
            night,
            CancellationToken.None);

        Assert.Contains(alerts, a => a.Type == AlertType.UnknownDestination && a.Title.Contains("hors horaires", StringComparison.OrdinalIgnoreCase));
    }
}
