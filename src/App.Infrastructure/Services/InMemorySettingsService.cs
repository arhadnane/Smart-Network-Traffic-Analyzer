using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

public sealed class InMemorySettingsService : ISettingsService
{
    private readonly Dictionary<string, object?> _store = new();

    public T Get<T>(string key, T @default)
    {
        if (_store.TryGetValue(key, out var value) && value is T t) return t;
        return @default;
    }

    public void Set<T>(string key, T value)
    {
        _store[key] = value;
    }
}
