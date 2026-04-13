using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Writes structured log output to the console.
/// </summary>
public sealed class ConsoleLoggingService : ILoggingService
{
    public void Error(string message, Exception? ex = null)
    {
        var exPart = ex is not null ? $" | Exception: {ex.GetType().Name}: {ex.Message}" : string.Empty;
        Console.Error.WriteLine($"[ERROR] {DateTimeOffset.UtcNow:o} {message}{exPart}");
    }

    public void Info(string message)
    {
        Console.WriteLine($"[INFO] {DateTimeOffset.UtcNow:o} {message}");
    }

    public void Warn(string message)
    {
        Console.WriteLine($"[WARN] {DateTimeOffset.UtcNow:o} {message}");
    }
}