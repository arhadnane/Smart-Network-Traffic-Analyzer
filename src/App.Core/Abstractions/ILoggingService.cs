namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

/// <summary>
/// Structured logging abstraction for the application.
/// </summary>
public interface ILoggingService
{
    void Info(string message);
    void Warn(string message);
    void Error(string message, Exception? ex = null);
}