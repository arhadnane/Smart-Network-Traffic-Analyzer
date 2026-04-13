using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Learns baseline traffic patterns per process and flags statistical anomalies.
/// Uses a sliding window of historical samples to compute per-process norms for:
/// - Connection frequency
/// - Bytes transferred
/// - Destination diversity
/// - Port usage
/// </summary>
public sealed class NetworkBaselineService : INetworkBaselineService
{
    private static readonly TimeSpan BaselineWindow = TimeSpan.FromHours(1);
    private const int MinSamplesForBaseline = 10;
    private const double FrequencyAnomalyThreshold = 3.0; // 3x the normal rate
    private const double VolumeAnomalyThreshold = 4.0;    // 4x the normal volume
    private const int MaxNewDestinationsPerMinute = 10;

    private readonly ConcurrentDictionary<string, ProcessBaseline> _baselines = new(StringComparer.OrdinalIgnoreCase);

    public void RecordSample(string processName, string remoteIp, int port, long bytesOut, DateTime timestamp)
    {
        var baseline = _baselines.GetOrAdd(processName, _ => new ProcessBaseline());
        baseline.AddSample(remoteIp, port, bytesOut, timestamp);
    }

    public Task<SecurityAlert[]> EvaluateAsync(string processName, string remoteIp, int port, long bytesOut, DateTime timestamp, CancellationToken ct = default)
    {
        if (ct.IsCancellationRequested)
            return Task.FromCanceled<SecurityAlert[]>(ct);

        if (!_baselines.TryGetValue(processName, out var baseline))
            return Task.FromResult(Array.Empty<SecurityAlert>());

        var alerts = new List<SecurityAlert>();
        var snapshot = baseline.GetSnapshot(timestamp);

        if (snapshot.SampleCount < MinSamplesForBaseline)
            return Task.FromResult(Array.Empty<SecurityAlert>());

        // 1. Connection frequency anomaly
        var currentRate = snapshot.ConnectionsLastMinute;
        var avgRate = snapshot.AverageConnectionsPerMinute;
        if (avgRate > 0 && currentRate > avgRate * FrequencyAnomalyThreshold)
        {
            alerts.Add(new SecurityAlert(
                AlertType.AbnormalTrafficPattern,
                RiskLevel.Medium,
                "Frequence de connexion anormale",
                $"{processName}: {currentRate} conn/min vs moyenne de {avgRate:F1}/min ({currentRate / avgRate:F1}x)",
                DateTime.UtcNow, remoteIp, processName));
        }

        // 2. Volume anomaly vs baseline
        if (snapshot.AverageBytes > 0 && bytesOut > snapshot.AverageBytes * VolumeAnomalyThreshold)
        {
            var ratio = bytesOut / snapshot.AverageBytes;
            alerts.Add(new SecurityAlert(
                AlertType.DataExfiltration,
                ratio > 10 ? RiskLevel.High : RiskLevel.Medium,
                "Volume de transfert anormal vs baseline",
                $"{processName}: {bytesOut / 1_000_000d:F1} MB vs baseline de {snapshot.AverageBytes / 1_000_000d:F2} MB ({ratio:F1}x)",
                DateTime.UtcNow, remoteIp, processName));
        }

        // 3. Destination diversity spike — suddenly contacting many new IPs
        if (snapshot.NewDestinationsLastMinute > MaxNewDestinationsPerMinute)
        {
            alerts.Add(new SecurityAlert(
                AlertType.AbnormalTrafficPattern,
                RiskLevel.High,
                "Diversification soudaine des destinations",
                $"{processName} a contacte {snapshot.NewDestinationsLastMinute} nouvelles IPs en 1 min (seuil: {MaxNewDestinationsPerMinute})",
                DateTime.UtcNow, remoteIp, processName));
        }

        // 4. Unusual port for this process
        if (snapshot.CommonPorts.Count >= 3 && !snapshot.CommonPorts.Contains(port))
        {
            alerts.Add(new SecurityAlert(
                AlertType.AbnormalTrafficPattern,
                RiskLevel.Low,
                "Port inhabituel pour ce processus",
                $"{processName} utilise le port {port} (ports habituels: {string.Join(", ", snapshot.CommonPorts.Take(5))})",
                DateTime.UtcNow, remoteIp, processName));
        }

        return Task.FromResult(alerts.ToArray());
    }

    internal sealed class ProcessBaseline
    {
        private readonly object _lock = new();
        private readonly LinkedList<Sample> _samples = new();
        private readonly HashSet<string> _knownDestinations = new(StringComparer.Ordinal);
        private readonly Dictionary<int, int> _portUsage = new();

        public void AddSample(string remoteIp, int port, long bytesOut, DateTime timestamp)
        {
            lock (_lock)
            {
                _samples.AddLast(new Sample(remoteIp, port, bytesOut, timestamp));
                _knownDestinations.Add(remoteIp);

                if (!_portUsage.ContainsKey(port))
                    _portUsage[port] = 0;
                _portUsage[port]++;

                Trim(timestamp);
            }
        }

        public BaselineSnapshot GetSnapshot(DateTime reference)
        {
            lock (_lock)
            {
                Trim(reference);

                var count = _samples.Count;
                if (count == 0)
                    return new BaselineSnapshot(0, 0, 0, 0, 0, new HashSet<int>());

                var firstTs = _samples.First!.Value.Timestamp;
                var windowMinutes = Math.Max(1, (reference - firstTs).TotalMinutes);

                var avgBytesPerConnection = _samples.Average(s => (double)s.BytesOut);
                var connectionsPerMinute = count / windowMinutes;

                var oneMinuteAgo = reference.AddMinutes(-1);
                var recentSamples = _samples.Where(s => s.Timestamp >= oneMinuteAgo).ToList();
                var currentConnsPerMin = recentSamples.Count;

                // Count new destinations in last minute — destinations not seen before this minute
                var destinationsBefore = new HashSet<string>(StringComparer.Ordinal);
                foreach (var s in _samples)
                {
                    if (s.Timestamp < oneMinuteAgo)
                        destinationsBefore.Add(s.RemoteIp);
                }
                var newDestsLastMin = recentSamples.Select(s => s.RemoteIp).Distinct(StringComparer.Ordinal)
                    .Count(ip => !destinationsBefore.Contains(ip));

                // Most common ports
                var commonPorts = _portUsage
                    .OrderByDescending(kv => kv.Value)
                    .Take(10)
                    .Select(kv => kv.Key)
                    .ToHashSet();

                return new BaselineSnapshot(count, avgBytesPerConnection, connectionsPerMinute, currentConnsPerMin, newDestsLastMin, commonPorts);
            }
        }

        private void Trim(DateTime reference)
        {
            var cutoff = reference - BaselineWindow;
            while (_samples.First is { Value: var s } && s.Timestamp < cutoff)
                _samples.RemoveFirst();
        }
    }

    internal readonly record struct Sample(string RemoteIp, int Port, long BytesOut, DateTime Timestamp);

    internal readonly record struct BaselineSnapshot(
        int SampleCount,
        double AverageBytes,
        double AverageConnectionsPerMinute,
        int ConnectionsLastMinute,
        int NewDestinationsLastMinute,
        HashSet<int> CommonPorts);
}
