using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using OxyPlot;
using OxyPlot.Axes;
using OxyPlot.Series;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.UI.Models;

namespace SmartNetworkTrafficAnalyzer.UI.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly IConnectionMonitor _monitor;
    private readonly IDnsResolver _dns;
    private readonly IReputationService _rep;
    private readonly IGeoService _geo;
    private CancellationTokenSource? _cts;

    public ObservableCollection<ConnectionItem> Connections { get; } = new();
    public PlotModel BandwidthModel { get; } = new PlotModel { Title = "Live Bandwidth" };

    public MainViewModel(IConnectionMonitor monitor, IDnsResolver dns, IReputationService rep)
    {
        _monitor = monitor;
        _dns = dns;
        _rep = rep;
        _geo = SmartNetworkTrafficAnalyzer.UI.App.Services.GetRequiredService<IGeoService>();
        SetupChart();
        _ = StartMonitoringAsync();
    }

    // Parameterless ctor for XAML that resolves services from App.Services
    public MainViewModel() : this(
        SmartNetworkTrafficAnalyzer.UI.App.Services.GetRequiredService<IConnectionMonitor>(),
        SmartNetworkTrafficAnalyzer.UI.App.Services.GetRequiredService<IDnsResolver>(),
        SmartNetworkTrafficAnalyzer.UI.App.Services.GetRequiredService<IReputationService>())
    { }

    private async Task StartMonitoringAsync()
    {
        try
        {
            _cts = new CancellationTokenSource();
            Console.WriteLine("[MainViewModel] Starting connection monitoring...");
            
            await foreach (var c in _monitor.GetLiveConnectionsAsync(_cts.Token))
            {
                var item = new ConnectionItem(c);
                
                // Always use dispatcher for UI thread safety
                System.Windows.Application.Current?.Dispatcher.BeginInvoke(() =>
                {
                    Connections.Add(item);
                    Console.WriteLine($"[MainViewModel] Added connection: {item.RemoteIp}:{item.RemotePort}");
                });

                // Simple bandwidth point (use BytesOut as a proxy)
                AddBandwidthPoint(item.BytesOut);

                // Enrich asynchronously without blocking the main loop
                _ = Task.Run(() => EnrichAsync(item));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MainViewModel] Error in monitoring: {ex.Message}");
        }
    }    private async Task EnrichAsync(ConnectionItem item)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var host = await _dns.ReverseLookupAsync(item.RemoteIp, cts.Token);
            
            System.Windows.Application.Current?.Dispatcher.BeginInvoke(() =>
            {
                item.Hostname = host;
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MainViewModel] DNS error for {item.RemoteIp}: {ex.Message}");
        }
        
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
            var rep = await _rep.CheckAsync(item.RemoteIp, cts.Token);
            
            System.Windows.Application.Current?.Dispatcher.BeginInvoke(() =>
            {
                item.Risk = rep.RiskLevel;
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MainViewModel] Reputation error for {item.RemoteIp}: {ex.Message}");
        }
        
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var geo = await _geo.LookupAsync(item.RemoteIp, cts.Token);
            
            System.Windows.Application.Current?.Dispatcher.BeginInvoke(() =>
            {
                item.Country = geo.Country;
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MainViewModel] Geo error for {item.RemoteIp}: {ex.Message}");
        }
    }

    private LineSeries _series = null!;
    private DateTimeAxis _timeAxis = null!;
    private void SetupChart()
    {
        _timeAxis = new DateTimeAxis { Position = AxisPosition.Bottom, StringFormat = "HH:mm:ss" };
        var y = new LinearAxis { Position = AxisPosition.Left, Title = "Bytes/s" };
        _series = new LineSeries { Title = "Out" };
        BandwidthModel.Axes.Add(_timeAxis);
        BandwidthModel.Axes.Add(y);
        BandwidthModel.Series.Add(_series);
    }

    private void AddBandwidthPoint(double value)
    {
        var x = DateTimeAxis.ToDouble(DateTime.Now);
        _series.Points.Add(new DataPoint(x, value));
        BandwidthModel.InvalidatePlot(true);
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Raise([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
