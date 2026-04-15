using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace SmartNetworkTrafficAnalyzer.UI.Converters;

/// <summary>
/// Converts a process name to a light background color for DataGrid rows.
/// Colors are subtle (alpha ~25-35) so text remains fully readable.
/// </summary>
public sealed class ProcessColorConverter : IValueConverter
{
    public static readonly ProcessColorConverter Instance = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not string name || string.IsNullOrWhiteSpace(name))
            return Brushes.Transparent;

        var lower = name.ToLowerInvariant();

        // Browsers — blue tones
        if (lower.Contains("chrome") || lower.Contains("chromium"))
            return MakeBrush(66, 133, 244);
        if (lower.Contains("msedge") || lower.Contains("edge"))
            return MakeBrush(0, 120, 212);
        if (lower.Contains("firefox"))
            return MakeBrush(255, 113, 57);

        // Windows system
        if (lower.Contains("svchost") || lower == "system" || lower.Contains("lsass") || lower.Contains("csrss")
            || lower.Contains("wininit") || lower.Contains("services"))
            return MakeBrush(108, 117, 125);
        if (lower.Contains("explorer"))
            return MakeBrush(255, 193, 7);
        if (lower.Contains("searchhost") || lower.Contains("searchapp") || lower.Contains("cortana"))
            return MakeBrush(0, 120, 212);
        if (lower.Contains("defender") || lower.Contains("msmpeng") || lower.Contains("securityhealth"))
            return MakeBrush(76, 175, 80);

        // Communication
        if (lower.Contains("teams") || lower.Contains("msteams"))
            return MakeBrush(98, 100, 167);
        if (lower.Contains("discord"))
            return MakeBrush(88, 101, 242);
        if (lower.Contains("slack"))
            return MakeBrush(74, 21, 75);
        if (lower.Contains("outlook") || lower.Contains("thunderbird"))
            return MakeBrush(0, 114, 198);

        // Media
        if (lower.Contains("spotify"))
            return MakeBrush(30, 215, 96);
        if (lower.Contains("steam") || lower.Contains("epicgames"))
            return MakeBrush(27, 40, 56);

        // Cloud
        if (lower.Contains("onedrive") || lower.Contains("dropbox") || lower.Contains("googledrive"))
            return MakeBrush(0, 120, 212);

        // Dev tools
        if (lower.Contains("code") || lower.Contains("devenv") || lower.Contains("rider")
            || lower.Contains("jetbrains") || lower.Contains("idea"))
            return MakeBrush(0, 122, 204);

        // Runtime / server
        if (lower.Contains("node") || lower.Contains("python") || lower.Contains("java")
            || lower.Contains("dotnet") || lower.Contains("w3wp"))
            return MakeBrush(104, 159, 56);

        // Database
        if (lower.Contains("sql") || lower.Contains("postgres") || lower.Contains("mysql")
            || lower.Contains("mongo") || lower.Contains("redis"))
            return MakeBrush(255, 152, 0);

        return Brushes.Transparent;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();

    private static SolidColorBrush MakeBrush(byte r, byte g, byte b)
        => new(Color.FromArgb(30, r, g, b));
}
