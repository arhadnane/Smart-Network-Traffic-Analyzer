using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using Microsoft.Extensions.DependencyInjection;
using OxyPlot;
using OxyPlot.Axes;
using OxyPlot.Series;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.UI.Models;

namespace SmartNetworkTrafficAnalyzer.UI.ViewModels;

/// <summary>
/// Main view model: orchestrates monitoring, enrichment, and security analysis.
/// </summary>
public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly IConnectionMonitor _monitor;
    private readonly IDnsResolver _dns;
    private readonly IReputationService _rep;
    private readonly IGeoService _geo;
    private readonly IOllamaAnalysisService _ollama;
    private readonly ISecurityAnalysisService _securityAnalysis;
    private readonly ILoggingService _logger;
    private CancellationTokenSource? _cts;
    private ConnectionItem? _selectedConnection;
    private bool _isMonitoring;
    private int _totalConnections;

    public ObservableCollection<ConnectionItem> Connections { get; } = new();
    public PlotModel BandwidthModel { get; } = new() { Title = "Live Bandwidth" };

    public ConnectionItem? SelectedConnection
    {
        get => _selectedConnection;
        set
        {
            if (_selectedConnection != value)
            {
                _selectedConnection = value;
                Raise();
                if (value is not null && string.IsNullOrEmpty(value.OllamaAnalysis))
                {
                    _ = AnalyzeConnectionWithOllamaAsync(value);
                }
            }
        }
    }

    public bool IsMonitoring
    {
        get => _isMonitoring;
        private set { if (_isMonitoring != value) { _isMonitoring = value; Raise(); } }
    }

    public int TotalConnections
    {
        get => _totalConnections;
        private set { if (_totalConnections != value) { _totalConnections = value; Raise(); } }
    }

    public MainViewModel(
        IConnectionMonitor monitor,
        IDnsResolver dns,
        IReputationService rep,
        IGeoService geo,
        IOllamaAnalysisService ollama,
        ISecurityAnalysisService securityAnalysis,
        ILoggingService logger)
    {
        _monitor = monitor;
        _dns = dns;
        _rep = rep;
        _geo = geo;
        _ollama = ollama;
        _securityAnalysis = securityAnalysis;
        _logger = logger;
        SetupChart();
        _ = StartMonitoringAsync();
    }

    public MainViewModel() : this(
        App.Services.GetRequiredService<IConnectionMonitor>(),
        App.Services.GetRequiredService<IDnsResolver>(),
        App.Services.GetRequiredService<IReputationService>(),
        App.Services.GetRequiredService<IGeoService>(),
        App.Services.GetRequiredService<IOllamaAnalysisService>(),
        App.Services.GetRequiredService<ISecurityAnalysisService>(),
        App.Services.GetRequiredService<ILoggingService>())
    {
    }

    private async Task StartMonitoringAsync()
    {
        if (IsMonitoring) return;
        IsMonitoring = true;

        try
        {
            _cts = new CancellationTokenSource();
            _logger.Info("Starting connection monitoring...");

            await foreach (var c in _monitor.GetLiveConnectionsAsync(_cts.Token))
            {
                var item = new ConnectionItem(c);

                Application.Current?.Dispatcher.BeginInvoke(() =>
                {
                    Connections.Add(item);
                    TotalConnections = Connections.Count;
                });

                AddBandwidthPoint(item.BytesOut);
                _ = EnrichAsync(item);
            }
        }
        catch (OperationCanceledException) when (_cts?.Token.IsCancellationRequested == true)
        {
            _logger.Info("Monitoring stopped by user");
        }
        catch (Exception ex)
        {
            _logger.Error($"Error in monitoring: {ex.Message}", ex);
        }
        finally
        {
            IsMonitoring = false;
        }
    }

    private async Task EnrichAsync(ConnectionItem item)
    {
        // DNS enrichment
        try
        {
            using var dnsCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var host = await _dns.ReverseLookupAsync(item.RemoteIp, dnsCts.Token);
            Application.Current?.Dispatcher.BeginInvoke(() => { item.Hostname = host; });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Warn($"DNS error for {item.RemoteIp}: {ex.Message}");
        }

        // Reputation check
        try
        {
            using var repCts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
            var rep = await _rep.CheckAsync(item.RemoteIp, repCts.Token);
            Application.Current?.Dispatcher.BeginInvoke(() => { item.Risk = rep.RiskLevel; });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Warn($"Reputation error for {item.RemoteIp}: {ex.Message}");
        }

        // Geo lookup
        try
        {
            using var geoCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var geo = await _geo.LookupAsync(item.RemoteIp, geoCts.Token);
            Application.Current?.Dispatcher.BeginInvoke(() => { item.Country = geo.Country; });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Warn($"Geo error for {item.RemoteIp}: {ex.Message}");
        }

        // Security analysis (if public IP)
        if (IsPublicIP(item.RemoteIp))
        {
            try
            {
                var analysis = await _securityAnalysis.AnalyzeConnectionAsync(
                    item.RemoteIp, item.ProcessName, item.RemotePort, item.BytesOut, DateTime.UtcNow);
                Application.Current?.Dispatcher.BeginInvoke(() =>
                {
                    item.SecurityScore = analysis.Score.Value;
                    item.SecurityCategory = analysis.Category.Name;
                });
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.Warn($"Security analysis error for {item.RemoteIp}: {ex.Message}");
            }
        }
    }

    private async Task AnalyzeConnectionWithOllamaAsync(ConnectionItem connection)
    {
        if (!IsPublicIP(connection.RemoteIp)) return;

        try
        {
            var analysis = await _ollama.AnalyzeConnectionAsync(
                connection.RemoteIp,
                connection.ProcessName,
                connection.Hostname ?? "N/A",
                connection.Country ?? "N/A");

            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                connection.OllamaAnalysis = analysis;
            });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                connection.OllamaAnalysis = $"❌ Erreur d'analyse: {ex.Message}";
            });
        }
    }

    private static bool IsPublicIP(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var address)) return false;
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;

        return !(
            bytes[0] == 10 ||
            (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
            (bytes[0] == 192 && bytes[1] == 168) ||
            bytes[0] == 127
        );
    }

    #region Chart

    private LineSeries _series = null!;
    private DateTimeAxis _timeAxis = null!;

    private void SetupChart()
    {
        _timeAxis = new DateTimeAxis { Position = AxisPosition.Bottom, StringFormat = "HH:mm:ss" };
        var yAxis = new LinearAxis { Position = AxisPosition.Left, Title = "Bytes/s" };
        _series = new LineSeries { Title = "Out" };
        BandwidthModel.Axes.Add(_timeAxis);
        BandwidthModel.Axes.Add(yAxis);
        BandwidthModel.Series.Add(_series);
    }

    private void AddBandwidthPoint(double value)
    {
        var x = DateTimeAxis.ToDouble(DateTime.Now);
        _series.Points.Add(new DataPoint(x, value));
        BandwidthModel.InvalidatePlot(true);
    }

    #endregion

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Raise([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}