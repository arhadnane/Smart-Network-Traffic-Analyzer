namespace SmartNetworkTrafficAnalyzer.Core.Abstractions;

public interface ILoggingService
{
    void Info(string message);
    void Warn(string message);
    void Error(string message, Exception? ex = null);
}
