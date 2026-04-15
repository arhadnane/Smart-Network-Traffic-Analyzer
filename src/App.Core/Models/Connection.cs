namespace SmartNetworkTrafficAnalyzer.Core.Models;

public enum Protocol
{
    Tcp,
    Udp
}

public enum Direction
{
    Inbound,
    Outbound
}

/// <summary>
/// Represents a single observed network connection.
/// </summary>
public record Connection(
    string Id,
    int SequentialId,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    Direction Direction,
    string LocalEndpoint,
    string RemoteIp,
    int RemotePort,
    Protocol Protocol,
    string ProcessName,
    int ProcessId,
    long BytesIn,
    long BytesOut,
    string? ProcessPath = null,
    string? ProcessDescription = null,
    string? ProcessCompany = null,
    string? ProcessWindowTitle = null
);