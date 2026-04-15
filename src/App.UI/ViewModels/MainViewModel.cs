using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using Microsoft.Extensions.DependencyInjection;
using OxyPlot;
using OxyPlot.Axes;
using OxyPlot.Series;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using SmartNetworkTrafficAnalyzer.UI.Models;
using SmartNetworkTrafficAnalyzer.UI.Resources;

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
    private readonly IIpScanService _ipScan;
    private readonly ISettingsService _settings;
    private readonly ILoggingService _logger;
    private CancellationTokenSource? _cts;
    private ConnectionItem? _selectedConnection;
    private string _selectedOllamaModel;
    private bool _isLoadingOllamaModels;
    private bool _isMonitoring;
    private int _totalConnections;
    private string _searchText = string.Empty;
    private string _currentLanguage;

    public ObservableCollection<ConnectionItem> Connections { get; } = new();
    public ObservableCollection<string> AvailableOllamaModels { get; } = new();
    public PlotModel BandwidthModel { get; } = new() { Title = "Live Bandwidth" };
    public ICollectionView ConnectionsView { get; }

    public ConnectionItem? SelectedConnection
    {
        get => _selectedConnection;
        set
        {
            if (_selectedConnection != value)
            {
                _selectedConnection = value;
                Raise();
                if (value is not null && NeedsOllamaAnalysis(value))
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

    public bool IsLoadingOllamaModels
    {
        get => _isLoadingOllamaModels;
        private set { if (_isLoadingOllamaModels != value) { _isLoadingOllamaModels = value; Raise(); Raise(nameof(OllamaModelsStatus)); } }
    }

    public string OllamaModelsStatus => IsLoadingOllamaModels
        ? Loc.I.LoadingModels
        : string.Format(Loc.I.ModelsAvailableFmt, AvailableOllamaModels.Count);

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (_searchText != value)
            {
                _searchText = value;
                Raise();
                ConnectionsView.Refresh();
            }
        }
    }

    public string CurrentLanguage
    {
        get => _currentLanguage;
        set
        {
            if (_currentLanguage == value) return;
            _currentLanguage = value;
            _settings.Set("app.language", value);
            Loc.I.Language = value;
            Raise();
            Raise(nameof(OllamaModelsStatus));
        }
    }

    public string SelectedOllamaModel
    {
        get => _selectedOllamaModel;
        set
        {
            if (string.IsNullOrWhiteSpace(value) || string.Equals(_selectedOllamaModel, value, StringComparison.Ordinal))
            {
                return;
            }

            _selectedOllamaModel = value;
            _ollama.SetSelectedModel(value);
            Raise();

            if (_selectedConnection is not null && IsPublicIP(_selectedConnection.RemoteIp))
            {
                _ = AnalyzeConnectionWithOllamaAsync(_selectedConnection);
            }
        }
    }

    public MainViewModel(
        IConnectionMonitor monitor,
        IDnsResolver dns,
        IReputationService rep,
        IGeoService geo,
        IOllamaAnalysisService ollama,
        ISecurityAnalysisService securityAnalysis,
        IIpScanService ipScan,
        ISettingsService settings,
        ILoggingService logger)
    {
        _monitor = monitor;
        _dns = dns;
        _rep = rep;
        _geo = geo;
        _ollama = ollama;
        _securityAnalysis = securityAnalysis;
        _ipScan = ipScan;
        _settings = settings;
        _logger = logger;
        _selectedOllamaModel = ollama.SelectedModel;
        _currentLanguage = settings.Get("app.language", "en");
        Loc.I.Language = _currentLanguage;

        ConnectionsView = CollectionViewSource.GetDefaultView(Connections);
        ConnectionsView.Filter = FilterConnection;

        SetupChart();
        _ = RefreshOllamaModelsAsync();
        _ = StartMonitoringAsync();
    }

    public MainViewModel() : this(
        App.Services.GetRequiredService<IConnectionMonitor>(),
        App.Services.GetRequiredService<IDnsResolver>(),
        App.Services.GetRequiredService<IReputationService>(),
        App.Services.GetRequiredService<IGeoService>(),
        App.Services.GetRequiredService<IOllamaAnalysisService>(),
        App.Services.GetRequiredService<ISecurityAnalysisService>(),
        App.Services.GetRequiredService<IIpScanService>(),
        App.Services.GetRequiredService<ISettingsService>(),
        App.Services.GetRequiredService<ILoggingService>())
    {
    }

    #region Monitoring

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

    #endregion

    #region Ollama Analysis

    private async Task AnalyzeConnectionWithOllamaAsync(ConnectionItem connection)
    {
        if (!IsPublicIP(connection.RemoteIp)) return;

        try
        {
            var model = SelectedOllamaModel;
            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                connection.OllamaAnalysis = string.Format(Loc.I.AnalyzingWithFmt, model);
                connection.OllamaModelUsed = model;
            });

            var analysis = await _ollama.AnalyzeConnectionAsync(
                new ConnectionAnalysisContext(
                    connection.RemoteIp,
                    connection.ProcessName,
                    connection.ProcessId,
                    connection.Hostname,
                    connection.Country,
                    connection.RemotePort,
                    connection.Direction.ToString(),
                    connection.BytesIn,
                    connection.BytesOut,
                    connection.ProcessPath,
                    connection.ProcessDescription,
                    connection.ProcessCompany,
                    connection.ProcessWindowTitle));

            if (string.IsNullOrWhiteSpace(analysis))
            {
                analysis = Loc.I.EmptyAnalysis;
            }

            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                connection.OllamaAnalysis = analysis;
                connection.OllamaModelUsed = model;
            });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                connection.OllamaAnalysis = $"❌ {ex.Message}";
                connection.OllamaModelUsed = SelectedOllamaModel;
            });
        }
    }

    public async Task ReanalyzeSelectedConnectionAsync()
    {
        if (_selectedConnection is null) return;
        await AnalyzeConnectionWithOllamaAsync(_selectedConnection);
    }

    private bool NeedsOllamaAnalysis(ConnectionItem connection)
    {
        return string.IsNullOrWhiteSpace(connection.OllamaAnalysis)
            || !string.Equals(connection.OllamaModelUsed, SelectedOllamaModel, StringComparison.Ordinal);
    }

    public Task RefreshOllamaModelsAsync() => LoadOllamaModelsAsync();

    private async Task LoadOllamaModelsAsync()
    {
        if (IsLoadingOllamaModels) return;

        try
        {
            IsLoadingOllamaModels = true;
            var models = await _ollama.GetAvailableModelsAsync();
            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                AvailableOllamaModels.Clear();
                foreach (var model in models)
                    AvailableOllamaModels.Add(model);

                if (!AvailableOllamaModels.Contains(SelectedOllamaModel, StringComparer.OrdinalIgnoreCase))
                    AvailableOllamaModels.Insert(0, SelectedOllamaModel);

                Raise(nameof(OllamaModelsStatus));
            });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Warn($"Unable to load Ollama models: {ex.Message}");
        }
        finally
        {
            IsLoadingOllamaModels = false;
        }
    }

    #endregion

    #region IP Scan

    public async Task ScanSelectedIpAsync()
    {
        var conn = _selectedConnection;
        if (conn is null || !IsPublicIP(conn.RemoteIp)) return;

        try
        {
            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                conn.IpScanInfo = Loc.I.ScanningIp;
            });

            var result = await _ipScan.ScanAsync(conn.RemoteIp);

            var sb = new StringBuilder();
            if (result.FlagEmoji is not null) sb.AppendLine($"🏳️ {result.FlagEmoji} {result.Country ?? ""} ({result.CountryCode ?? ""})");
            if (result.City is not null) sb.AppendLine($"🏙️ {result.City}, {result.Region ?? ""}");
            if (result.Isp is not null) sb.AppendLine($"📡 ISP: {result.Isp}");
            if (result.Organization is not null) sb.AppendLine($"🏢 Org: {result.Organization}");
            if (result.Domain is not null) sb.AppendLine($"🌐 Domain: {result.Domain}");
            if (result.Timezone is not null) sb.AppendLine($"🕐 TZ: {result.Timezone}");
            if (result.Latitude.HasValue) sb.AppendLine($"📍 {result.Latitude:F4}, {result.Longitude:F4}");
            if (result.IsEu.HasValue) sb.AppendLine($"🇪🇺 EU: {(result.IsEu.Value ? "Yes" : "No")}");

            var text = sb.Length > 0 ? sb.ToString().TrimEnd() : "No data available";

            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                conn.IpScanInfo = text;
            });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                conn.IpScanInfo = $"❌ {ex.Message}";
            });
        }
    }

    #endregion

    #region Search

    private bool FilterConnection(object obj)
    {
        if (string.IsNullOrWhiteSpace(_searchText)) return true;
        if (obj is not ConnectionItem c) return false;

        return c.RemoteIp.Contains(_searchText, StringComparison.OrdinalIgnoreCase)
            || c.ProcessName.Contains(_searchText, StringComparison.OrdinalIgnoreCase)
            || (c.Hostname?.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ?? false)
            || (c.Country?.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ?? false)
            || c.RemotePort.ToString().Contains(_searchText, StringComparison.OrdinalIgnoreCase)
            || c.ProcessId.ToString().Contains(_searchText, StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region Summary

    public string GenerateSummary()
    {
        var loc = Loc.I;
        var items = Connections.ToArray();
        var sb = new StringBuilder();

        sb.AppendLine($"═══ {loc.SummaryTitle} ═══");
        sb.AppendLine();
        sb.AppendLine($"📊 {loc.TotalConnections}: {items.Length}");

        var uniqueIps = items.Select(c => c.RemoteIp).Distinct().Count();
        sb.AppendLine($"🌐 {loc.UniqueIps}: {uniqueIps}");

        var uniqueProcesses = items.Select(c => c.ProcessName).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        sb.AppendLine($"⚙️ {loc.UniqueProcesses}: {uniqueProcesses}");

        var countries = items.Where(c => !string.IsNullOrWhiteSpace(c.Country))
            .Select(c => c.Country!).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        sb.AppendLine($"🌍 {loc.Countries}: {countries}");

        // High risk
        var highRisk = items.Count(c => c.Risk is RiskLevel.High or RiskLevel.Malicious);
        sb.AppendLine($"🔴 {loc.HighRisk}: {highRisk}");

        sb.AppendLine();
        sb.AppendLine($"── {loc.TopProcesses} ──");
        foreach (var g in items.GroupBy(c => c.ProcessName, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).Take(10))
        {
            sb.AppendLine($"  {g.First().ProcessIcon} {g.Key}: {g.Count()}");
        }

        sb.AppendLine();
        sb.AppendLine($"── {loc.TopCountries} ──");
        foreach (var g in items.Where(c => !string.IsNullOrWhiteSpace(c.Country))
            .GroupBy(c => c.Country!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).Take(10))
        {
            sb.AppendLine($"  {g.Key}: {g.Count()}");
        }

        sb.AppendLine();
        sb.AppendLine($"── {loc.TopIps} ──");
        foreach (var g in items.GroupBy(c => c.RemoteIp)
            .OrderByDescending(g => g.Count()).Take(10))
        {
            var host = g.First().Hostname ?? "";
            sb.AppendLine($"  {g.Key} ({host}): {g.Count()}");
        }

        return sb.ToString();
    }

    #endregion

    #region Language

    public void ToggleLanguage()
    {
        CurrentLanguage = CurrentLanguage == "fr" ? "en" : "fr";
    }

    #endregion

    #region Helpers

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

    #endregion

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