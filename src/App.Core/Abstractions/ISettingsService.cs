namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

public interface ISettingsService
{
    T Get<T>(string key, T @default);
    void Set<T>(string key, T value);
}
