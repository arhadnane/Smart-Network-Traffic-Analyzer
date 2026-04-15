using System.Windows;
using SmartNetworkTrafficAnalyzer.UI.Models;
using SmartNetworkTrafficAnalyzer.UI.Resources;
using SmartNetworkTrafficAnalyzer.UI.ViewModels;

namespace SmartNetworkTrafficAnalyzer.UI;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private MainViewModel Vm => (MainViewModel)DataContext;

    private async void OllamaModelComboBox_OnDropDownOpened(object sender, EventArgs e)
    {
        await Vm.RefreshOllamaModelsAsync();
    }

    private async void ReanalyzeSelection_OnClick(object sender, RoutedEventArgs e)
    {
        await Vm.ReanalyzeSelectedConnectionAsync();
    }

    private void LanguageToggle_OnClick(object sender, RoutedEventArgs e)
    {
        Vm.ToggleLanguage();
    }

    private void Summary_OnClick(object sender, RoutedEventArgs e)
    {
        var summary = Vm.GenerateSummary();
        var win = new Window
        {
            Title = Loc.I.SummaryTitle,
            Width = 550,
            Height = 650,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            Content = new System.Windows.Controls.ScrollViewer
            {
                Padding = new Thickness(16),
                Content = new System.Windows.Controls.TextBlock
                {
                    Text = summary,
                    TextWrapping = TextWrapping.Wrap,
                    FontFamily = new System.Windows.Media.FontFamily("Segoe UI"),
                    FontSize = 13,
                    LineHeight = 22
                }
            }
        };
        win.ShowDialog();
    }

    private async void ScanIp_OnClick(object sender, RoutedEventArgs e)
    {
        await Vm.ScanSelectedIpAsync();
    }

    private void CopyIp_OnClick(object sender, RoutedEventArgs e)
    {
        if (grid.SelectedItem is ConnectionItem item)
            Clipboard.SetText(item.RemoteIp);
    }

    private void CopyHostname_OnClick(object sender, RoutedEventArgs e)
    {
        if (grid.SelectedItem is ConnectionItem item && !string.IsNullOrWhiteSpace(item.Hostname))
            Clipboard.SetText(item.Hostname);
    }

    private void CopyProcessName_OnClick(object sender, RoutedEventArgs e)
    {
        if (grid.SelectedItem is ConnectionItem item)
            Clipboard.SetText(item.ProcessName);
    }

    private void CopyPid_OnClick(object sender, RoutedEventArgs e)
    {
        if (grid.SelectedItem is ConnectionItem item)
            Clipboard.SetText(item.ProcessId.ToString());
    }
}