namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Simple key-value settings store.
/// </summary>
public interface ISettingsService
{
    T Get<T>(string key, T @default);
    void Set<T>(string key, T value);
}