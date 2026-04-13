using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Core.Tests.Models;

public class ConnectionTests
{
    [Fact]
    public void Connection_RecordEquality_Works()
    {
        var now = DateTimeOffset.UtcNow;
        var c1 = new Connection("abc", 1, now, now, Direction.Outbound, "127.0.0.1:5000", "8.8.8.8", 443, Protocol.Tcp, "chrome", 1234, 1000, 2000);
        var c2 = new Connection("abc", 1, now, now, Direction.Outbound, "127.0.0.1:5000", "8.8.8.8", 443, Protocol.Tcp, "chrome", 1234, 1000, 2000);
        Assert.Equal(c1, c2);
    }

    [Fact]
    public void Connection_Properties_SetCorrectly()
    {
        var now = DateTimeOffset.UtcNow;
        var conn = new Connection("id1", 5, now, now, Direction.Inbound, "10.0.0.1:8080", "1.1.1.1", 53, Protocol.Udp, "stub", 42, 500, 300);

        Assert.Equal("id1", conn.Id);
        Assert.Equal(5, conn.SequentialId);
        Assert.Equal(Direction.Inbound, conn.Direction);
        Assert.Equal("1.1.1.1", conn.RemoteIp);
        Assert.Equal(53, conn.RemotePort);
        Assert.Equal(Protocol.Udp, conn.Protocol);
        Assert.Equal("stub", conn.ProcessName);
        Assert.Equal(42, conn.ProcessId);
        Assert.Equal(500, conn.BytesIn);
        Assert.Equal(300, conn.BytesOut);
    }

    [Theory]
    [InlineData(Direction.Inbound)]
    [InlineData(Direction.Outbound)]
    public void Connection_Direction_AllValuesValid(Direction direction)
    {
        var conn = CreateConnection(direction: direction);
        Assert.Equal(direction, conn.Direction);
    }

    [Theory]
    [InlineData(Protocol.Tcp)]
    [InlineData(Protocol.Udp)]
    public void Connection_Protocol_AllValuesValid(Protocol protocol)
    {
        var conn = CreateConnection(protocol: protocol);
        Assert.Equal(protocol, conn.Protocol);
    }

    private static Connection CreateConnection(
        string id = "test",
        int seqId = 1,
        Direction direction = Direction.Outbound,
        Protocol protocol = Protocol.Tcp) =>
        new(id, seqId, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, direction, "127.0.0.1:5000", "8.8.8.8", 443, protocol, "test", 1, 0, 0);
}

public class GeoInfoTests
{
    [Fact]
    public void GeoInfo_WithAllFields_SetCorrectly()
    {
        var now = DateTimeOffset.UtcNow;
        var geo = new GeoInfo("8.8.8.8", "US", "Mountain View", "AS15169", "Google", now);
        Assert.Equal("8.8.8.8", geo.Ip);
        Assert.Equal("US", geo.Country);
        Assert.Equal("Mountain View", geo.City);
        Assert.Equal("AS15169", geo.Asn);
        Assert.Equal("Google", geo.Provider);
    }

    [Fact]
    public void GeoInfo_WithNullOptionals_Works()
    {
        var geo = new GeoInfo("10.0.0.1", null, null, null, null, DateTimeOffset.UtcNow);
        Assert.Null(geo.Country);
        Assert.Null(geo.City);
        Assert.Null(geo.Asn);
        Assert.Null(geo.Provider);
    }
}

public class ReputationTests
{
    [Fact]
    public void Reputation_CleanLevel_Works()
    {
        var rep = new Reputation("8.8.8.8", RiskLevel.Clean, new Dictionary<string, string>(), DateTimeOffset.UtcNow);
        Assert.Equal(RiskLevel.Clean, rep.RiskLevel);
    }

    [Theory]
    [InlineData(RiskLevel.Clean)]
    [InlineData(RiskLevel.Low)]
    [InlineData(RiskLevel.Medium)]
    [InlineData(RiskLevel.High)]
    [InlineData(RiskLevel.Malicious)]
    public void Reputation_AllRiskLevels_Valid(RiskLevel level)
    {
        var rep = new Reputation("1.2.3.4", level, new Dictionary<string, string>(), DateTimeOffset.UtcNow);
        Assert.Equal(level, rep.RiskLevel);
    }
}

public class SecurityModelsTests
{
    [Fact]
    public void IPCategory_KnownGood_Works()
    {
        var cat = new IPCategory("Google Services", "Known CDN", RiskLevel.Low, IsKnownGood: true);
        Assert.True(cat.IsKnownGood);
        Assert.False(cat.IsKnownBad);
    }

    [Fact]
    public void IPCategory_KnownBad_Works()
    {
        var cat = new IPCategory("Tor Exit", "Known Tor node", RiskLevel.High, IsKnownBad: true);
        Assert.True(cat.IsKnownBad);
        Assert.False(cat.IsKnownGood);
    }

    [Fact]
    public void SecurityScore_ClampedValues()
    {
        var score = new SecurityScore(85, RiskLevel.Low, "Test", new Dictionary<string, double>());
        Assert.Equal(85, score.Value);
        Assert.Equal(RiskLevel.Low, score.Level);
    }

    [Fact]
    public void SecurityAlert_AllProperties()
    {
        var now = DateTime.UtcNow;
        var alert = new SecurityAlert(AlertType.VolumeAnomaly, RiskLevel.High, "Volume", "High volume", now, "1.2.3.4", "malware.exe");
        Assert.Equal(AlertType.VolumeAnomaly, alert.Type);
        Assert.Equal(RiskLevel.High, alert.Severity);
        Assert.Equal("1.2.3.4", alert.RelatedIP);
        Assert.Equal("malware.exe", alert.RelatedProcess);
    }
}