using System.ComponentModel;
using System.Runtime.CompilerServices;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.UI.Models;

public sealed class ConnectionItem : INotifyPropertyChanged
{
    private string? _hostname;
    private string? _country;
    private RiskLevel _risk;

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

    public RiskLevel Risk
    {
        get => _risk;
        set { if (_risk != value) { _risk = value; Raise(); } }
    }

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
