using System.Configuration;
using System.Data;
using System.Windows;

using Microsoft.Extensions.DependencyInjection;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;

namespace SmartNetworkTrafficAnalyzer.UI;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
	public static IServiceProvider Services { get; private set; } = default!;

	protected override void OnStartup(StartupEventArgs e)
	{
		base.OnStartup(e);

		var sc = new ServiceCollection();
		sc.AddSingleton<ISettingsService, InMemorySettingsService>();
		sc.AddSingleton<ILoggingService, ConsoleLoggingService>();
	sc.AddSingleton<IDnsResolver, SystemDnsResolver>();
		sc.AddSingleton<BlocklistReputationService>();
		sc.AddSingleton<IReputationService>(sp => new AggregatedReputationService(new IReputationService[]
		{
			sp.GetRequiredService<BlocklistReputationService>()
		}));
	sc.AddSingleton<IGeoService, IpApiGeoService>();
	sc.AddSingleton<IConnectionMonitor, WindowsTcpConnectionMonitor>();

		Services = sc.BuildServiceProvider();

		var main = new MainWindow();
		main.Show();
	}
}

