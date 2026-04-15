using System.Net.Http;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;

namespace SmartNetworkTrafficAnalyzer.UI;

/// <summary>
/// Application entry point with dependency injection configuration.
/// </summary>
public partial class App : Application
{
    public static IServiceProvider Services { get; private set; } = default!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var services = new ServiceCollection();

        // Core services
        services.AddSingleton<ISettingsService, InMemorySettingsService>();
        services.AddSingleton<ILoggingService, ConsoleLoggingService>();

        // Network services
        services.AddSingleton<IDnsResolver, SystemDnsResolver>();
        services.AddSingleton<IConnectionMonitor, WindowsTcpConnectionMonitor>();

        // Reputation services
        services.AddSingleton<BlocklistReputationService>();
        services.AddSingleton<IReputationService>(sp =>
        {
            var blocklist = sp.GetRequiredService<BlocklistReputationService>();
            var logger = sp.GetRequiredService<ILoggingService>();
            return new AggregatedReputationService(new IReputationService[] { blocklist }, logger);
        });

        // Geo service
        services.AddSingleton<IGeoService>(sp =>
        {
            var logger = sp.GetRequiredService<ILoggingService>();
            return new IpApiGeoService(new HttpClient(), logger);
        });

        // Security services
        services.AddSingleton<IIPCategorizationService, SimpleIPCategorizationService>();
        services.AddSingleton<ISecurityScoringService, SimpleSecurityScoringService>();
        services.AddSingleton<IAnomalyDetectionService, SimpleAnomalyDetectionService>();
        services.AddSingleton<ISecurityAnalysisService, SecurityAnalysisService>();
        services.AddSingleton<ThreatIntelligenceService>();

        // Ollama AI analysis
        services.AddSingleton<IOllamaAnalysisService>(sp =>
        {
            var logger = sp.GetRequiredService<ILoggingService>();
            var settings = sp.GetRequiredService<ISettingsService>();
            return new OllamaAnalysisService(new HttpClient(), logger, settings, model: OllamaAnalysisService.DefaultModel);
        });

        // IP scan service (ipwho.is — free, no API key)
        services.AddSingleton<IIpScanService>(sp =>
        {
            var logger = sp.GetRequiredService<ILoggingService>();
            return new IpWhoIsScanService(new HttpClient(), logger);
        });

        Services = services.BuildServiceProvider();

        var main = new MainWindow();
        main.Show();
    }
}