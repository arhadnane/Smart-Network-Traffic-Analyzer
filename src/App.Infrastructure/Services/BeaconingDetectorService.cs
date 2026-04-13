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
/// Detects C2 beaconing patterns by analyzing connection timing regularity.
/// Beacons are periodic callbacks made by malware to C2 servers at near-constant intervals.
/// </summary>
public sealed class BeaconingDetectorService : IBeaconingDetector
{
    private static readonly TimeSpan AnalysisWindow = TimeSpan.FromMinutes(30);
    private const int MinSamplesForDetection = 5;
    private const double MaxJitterPercent = 0.15; // 15% jitter tolerance
    private const double MinIntervalSeconds = 5;
    private const double MaxIntervalSeconds = 3600; // 1 hour

    private readonly ConcurrentDictionary<string, DestinationTimings> _timings = new(StringComparer.Ordinal);

    public void RecordConnection(string remoteIp, string processName, DateTime timestamp)
    {
        var entry = _timings.GetOrAdd(remoteIp, _ => new DestinationTimings());
        entry.Add(processName, timestamp);
    }

    public Task<SecurityAlert[]> DetectBeaconingAsync(string remoteIp, CancellationToken ct = default)
    {
        if (ct.IsCancellationRequested)
            return Task.FromCanceled<SecurityAlert[]>(ct);

        var alerts = new List<SecurityAlert>();

        if (!_timings.TryGetValue(remoteIp, out var timings))
            return Task.FromResult(Array.Empty<SecurityAlert>());

        var snapshot = timings.GetSnapshot(DateTime.UtcNow);

        foreach (var (process, timestamps) in snapshot)
        {
            if (timestamps.Count < MinSamplesForDetection)
                continue;

            var intervals = new List<double>();
            for (int i = 1; i < timestamps.Count; i++)
            {
                intervals.Add((timestamps[i] - timestamps[i - 1]).TotalSeconds);
            }

            if (intervals.Count < MinSamplesForDetection - 1)
                continue;

            var meanInterval = intervals.Average();

            // Ignore intervals too short or too long
            if (meanInterval < MinIntervalSeconds || meanInterval > MaxIntervalSeconds)
                continue;

            var stdDev = Math.Sqrt(intervals.Sum(x => Math.Pow(x - meanInterval, 2)) / intervals.Count);
            var coefficientOfVariation = stdDev / meanInterval;

            if (coefficientOfVariation <= MaxJitterPercent)
            {
                var severity = coefficientOfVariation <= 0.05 ? RiskLevel.High : RiskLevel.Medium;
                alerts.Add(new SecurityAlert(
                    AlertType.Beaconing,
                    severity,
                    "Beaconing C2 detecte",
                    $"{process} contacte {remoteIp} toutes les ~{meanInterval:F0}s (jitter {coefficientOfVariation:P1}, {timestamps.Count} echantillons)",
                    DateTime.UtcNow,
                    remoteIp,
                    process));
            }
            else if (coefficientOfVariation <= 0.30 && timestamps.Count >= 8)
            {
                // Looser threshold for more samples — could be jittered beaconing
                alerts.Add(new SecurityAlert(
                    AlertType.Beaconing,
                    RiskLevel.Low,
                    "Pattern periodique suspect",
                    $"{process} montre des connexions semi-regulieres vers {remoteIp} (~{meanInterval:F0}s +/- {stdDev:F1}s)",
                    DateTime.UtcNow,
                    remoteIp,
                    process));
            }
        }

        return Task.FromResult(alerts.ToArray());
    }

    private sealed class DestinationTimings
    {
        private readonly object _lock = new();
        private readonly Dictionary<string, List<DateTime>> _processTimings = new(StringComparer.OrdinalIgnoreCase);

        public void Add(string processName, DateTime timestamp)
        {
            lock (_lock)
            {
                if (!_processTimings.TryGetValue(processName, out var list))
                {
                    list = new List<DateTime>();
                    _processTimings[processName] = list;
                }
                list.Add(timestamp);
            }
        }

        public Dictionary<string, List<DateTime>> GetSnapshot(DateTime reference)
        {
            lock (_lock)
            {
                var cutoff = reference - AnalysisWindow;
                var result = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);

                foreach (var (process, timestamps) in _processTimings)
                {
                    var recent = timestamps.Where(t => t >= cutoff).OrderBy(t => t).ToList();
                    // Trim old entries from underlying list
                    timestamps.RemoveAll(t => t < cutoff);

                    if (recent.Count >= MinSamplesForDetection)
                        result[process] = recent;
                }

                return result;
            }
        }
    }
}
