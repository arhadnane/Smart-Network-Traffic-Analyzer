using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// In-memory key-value settings store (no persistence).
/// </summary>
public sealed class InMemorySettingsService : ISettingsService
{
    private readonly Dictionary<string, object?> _store = new();

    public T Get<T>(string key, T @default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (_store.TryGetValue(key, out var value) && value is T typed)
        {
            return typed;
        }

        return @default;
    }

    public void Set<T>(string key, T value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        _store[key] = value;
    }
}