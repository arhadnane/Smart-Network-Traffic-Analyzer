using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace SmartNetworkTrafficAnalyzer.UI.Models;

/// <summary>
/// UI model for security analysis display.
/// </summary>
public class SecurityItem : INotifyPropertyChanged
{
    private string _ipAddress = string.Empty;
    private string _category = string.Empty;
    private int _securityScore;
    private string _alerts = string.Empty;
    private string _threat = string.Empty;

    public string IPAddress
    {
        get => _ipAddress;
        set { _ipAddress = value; OnPropertyChanged(); }
    }

    public string Category
    {
        get => _category;
        set { _category = value; OnPropertyChanged(); }
    }

    public int SecurityScore
    {
        get => _securityScore;
        set { _securityScore = value; OnPropertyChanged(); OnPropertyChanged(nameof(SecurityLevel)); }
    }

    public string SecurityLevel => _securityScore switch
    {
        >= 90 => "✅ Sûr",
        >= 70 => "🟢 Légitime",
        >= 50 => "🟡 Neutre",
        >= 25 => "🟠 Suspect",
        _ => "🔴 Dangereux"
    };

    public string Alerts
    {
        get => _alerts;
        set { _alerts = value; OnPropertyChanged(); }
    }

    public string ThreatIntelligence
    {
        get => _threat;
        set { _threat = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}