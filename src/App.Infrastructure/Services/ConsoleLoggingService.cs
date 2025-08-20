using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

public sealed class ConsoleLoggingService : ILoggingService
{
    public void Error(string message, Exception? ex = null)
    {
        Console.Error.WriteLine($"[ERROR] {DateTimeOffset.Now:o} {message} {ex}");
    }

    public void Info(string message)
    {
        Console.WriteLine($"[INFO] {DateTimeOffset.Now:o} {message}");
    }

    public void Warn(string message)
    {
        Console.WriteLine($"[WARN] {DateTimeOffset.Now:o} {message}");
    }
}
