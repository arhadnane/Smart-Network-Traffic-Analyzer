using System.ComponentModel;
using System.Runtime.CompilerServices;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.UI.Models;

/// <summary>
/// UI-friendly wrapper for a Connection with bindable enrichment properties.
/// </summary>
public sealed class ConnectionItem : INotifyPropertyChanged
{
    private string? _hostname;
    private string? _country;
    private RiskLevel _risk;
    private string? _ollamaAnalysis;
    private string? _ollamaModelUsed;
    private string? _ipScanInfo;
    private int _securityScore;
    private string _securityCategory = string.Empty;

    public ConnectionItem(Connection c)
    {
        Id = c.Id;
        SequentialId = c.SequentialId;
        FirstSeen = c.FirstSeen;
        LastSeen = c.LastSeen;
        Direction = c.Direction;
        LocalEndpoint = c.LocalEndpoint;
        RemoteIp = c.RemoteIp;
        RemotePort = c.RemotePort;
        Protocol = c.Protocol;
        ProcessName = c.ProcessName;
        ProcessId = c.ProcessId;
        BytesIn = c.BytesIn;
        BytesOut = c.BytesOut;
        ProcessPath = c.ProcessPath;
        ProcessDescription = c.ProcessDescription;
        ProcessCompany = c.ProcessCompany;
        ProcessWindowTitle = c.ProcessWindowTitle;
    }

    public string Id { get; }
    public int SequentialId { get; }
    public DateTimeOffset FirstSeen { get; }
    public DateTimeOffset LastSeen { get; }
    public Direction Direction { get; }
    public string LocalEndpoint { get; }
    public string RemoteIp { get; }
    public int RemotePort { get; }
    public Protocol Protocol { get; }
    public string ProcessName { get; }
    public int ProcessId { get; }
    public long BytesIn { get; }
    public long BytesOut { get; }
    public string? ProcessPath { get; }
    public string? ProcessDescription { get; }
    public string? ProcessCompany { get; }
    public string? ProcessWindowTitle { get; }

    public RiskLevel Risk
    {
        get => _risk;
        set { if (_risk != value) { _risk = value; Raise(); Raise(nameof(RiskDisplay)); } }
    }

    public string RiskDisplay => Risk switch
    {
        RiskLevel.Clean => "✅ Clean",
        RiskLevel.Low => "🟢 Low",
        RiskLevel.Medium => "🟡 Medium",
        RiskLevel.High => "🟠 High",
        RiskLevel.Malicious => "🔴 Malicious",
        _ => "❓ Unknown"
    };

    public string? Hostname
    {
        get => _hostname;
        set { if (_hostname != value) { _hostname = value; Raise(); } }
    }

    public string? Country
    {
        get => _country;
        set { if (_country != value) { _country = value; Raise(); } }
    }

    public string? OllamaAnalysis
    {
        get => _ollamaAnalysis;
        set { if (_ollamaAnalysis != value) { _ollamaAnalysis = value; Raise(); } }
    }

    public string? OllamaModelUsed
    {
        get => _ollamaModelUsed;
        set { if (_ollamaModelUsed != value) { _ollamaModelUsed = value; Raise(); } }
    }

    public string? IpScanInfo
    {
        get => _ipScanInfo;
        set { if (_ipScanInfo != value) { _ipScanInfo = value; Raise(); } }
    }

    public string ProcessIcon => (ProcessName ?? "").ToLowerInvariant() switch
    {
        var n when n.Contains("chrome") || n.Contains("chromium") => "🌐",
        var n when n.Contains("msedge") || n.Contains("edge") => "🌐",
        var n when n.Contains("firefox") => "🦊",
        var n when n.Contains("svchost") => "⚙️",
        var n when n is "system" or "ntoskrnl" => "🖥️",
        var n when n.Contains("explorer") => "📁",
        var n when n.Contains("searchhost") || n.Contains("searchapp") => "🔍",
        var n when n.Contains("teams") || n.Contains("msteams") => "💬",
        var n when n.Contains("discord") => "💬",
        var n when n.Contains("slack") => "💬",
        var n when n.Contains("outlook") || n.Contains("thunderbird") => "📧",
        var n when n.Contains("spotify") => "🎵",
        var n when n.Contains("steam") || n.Contains("epicgames") => "🎮",
        var n when n.Contains("onedrive") || n.Contains("dropbox") => "☁️",
        var n when n.Contains("code") || n.Contains("devenv") || n.Contains("rider") => "💻",
        var n when n.Contains("defender") || n.Contains("msmpeng") => "🛡️",
        var n when n.Contains("node") || n.Contains("python") || n.Contains("dotnet") => "⚡",
        var n when n.Contains("sql") || n.Contains("postgres") || n.Contains("mysql") => "🗄️",
        _ => "📋"
    };

    public string ProcessDisplay => $"{ProcessIcon} {ProcessName}";

    public int SecurityScore
    {
        get => _securityScore;
        set { if (_securityScore != value) { _securityScore = value; Raise(); Raise(nameof(SecurityLevel)); } }
    }

    public string SecurityCategory
    {
        get => _securityCategory;
        set { if (_securityCategory != value) { _securityCategory = value; Raise(); } }
    }

    public string SecurityLevel => _securityScore switch
    {
        >= 90 => "✅ Sûr",
        >= 70 => "🟢 Légitime",
        >= 50 => "🟡 Neutre",
        >= 25 => "🟠 Suspect",
        _ => "🔴 Dangereux"
    };

    public string BytesInFormatted => FormatBytes(BytesIn);
    public string BytesOutFormatted => FormatBytes(BytesOut);

    private static string FormatBytes(long bytes)
    {
        if (bytes == 0) return "0 B";

        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        int order = 0;
        double size = bytes;

        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }

        return $"{size:0.##} {sizes[order]}";
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Raise([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}