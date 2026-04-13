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
/// Rich anomaly detector that keeps short-term history per destination to surface contextual alerts.
/// </summary>
public sealed class AnomalyDetectionService : IAnomalyDetectionService
{
	private static readonly TimeSpan HistoryWindow = TimeSpan.FromMinutes(15);
	private static readonly TimeSpan BurstWindow = TimeSpan.FromSeconds(30);
	private static readonly TimeSpan RecentWindow = TimeSpan.FromMinutes(5);
	private static readonly TimeSpan DormantWindow = TimeSpan.FromHours(12);

	private static readonly HashSet<int> SuspiciousPorts = new() { 6667, 6697, 1337, 31337, 4444, 5555, 9050, 9051 };
	private static readonly HashSet<int> DangerousPorts = new() { 23, 135, 139, 445, 1433, 3306, 3389 };
	private static readonly string[] SuspiciousProcessTokens = { "unknown", "temp", ".tmp", "svchost", "powershell", "cmd" };

	private readonly ConcurrentDictionary<string, DestinationStats> _destinations = new(StringComparer.Ordinal);

	public void RecordConnection(string remoteIp, string processName, int port, long bytesOut, DateTime connectionTime)
	{
		var stats = _destinations.GetOrAdd(remoteIp, _ => new DestinationStats(connectionTime));
		stats.AddSample(processName, port, bytesOut, connectionTime);
	}

	public Task<SecurityAlert[]> CheckAnomaliesAsync(
		string remoteIp,
		string processName,
		int port,
		long bytesOut,
		DateTime connectionTime,
		CancellationToken ct = default)
	{
		if (ct.IsCancellationRequested)
		{
			return Task.FromCanceled<SecurityAlert[]>(ct);
		}

		var alerts = new List<SecurityAlert>();
		var snapshot = _destinations.TryGetValue(remoteIp, out var stats)
			? stats.Snapshot(connectionTime)
			: (DestinationSnapshot?)null;

		AnalyzeVolume(snapshot, bytesOut, remoteIp, processName, alerts);
		AnalyzeBursts(snapshot, remoteIp, processName, port, alerts);
		AnalyzeNewOrDormantDestination(snapshot, remoteIp, processName, port, bytesOut, connectionTime, alerts);
		AnalyzeProcess(processName, remoteIp, bytesOut, snapshot, alerts);
		AnalyzePorts(port, remoteIp, processName, alerts);
		AnalyzeAfterHours(connectionTime, bytesOut, remoteIp, processName, alerts);

		return Task.FromResult(alerts.ToArray());
	}

	private static void AnalyzeVolume(DestinationSnapshot? snapshot, long bytesOut, string ip, string process, List<SecurityAlert> alerts)
	{
		if (bytesOut > 150_000_000)
		{
			alerts.Add(CreateAlert(AlertType.VolumeAnomaly, RiskLevel.High, "Exfiltration suspecte",
				$"{bytesOut / 1_000_000d:F1} MB envoyes vers {ip}", ip, process));
		}
		else if (bytesOut > 50_000_000)
		{
			alerts.Add(CreateAlert(AlertType.VolumeAnomaly, RiskLevel.Medium, "Volume de donnees eleve",
				$"{bytesOut / 1_000_000d:F1} MB envoyes vers {ip}", ip, process));
		}

		if (snapshot is { TotalConnections: >= 5, AverageBytes: > 0 })
		{
			var ratio = bytesOut / snapshot.Value.AverageBytes;
			if (ratio >= 6)
			{
				alerts.Add(CreateAlert(AlertType.VolumeAnomaly, RiskLevel.High, "Pic inhabituel",
					$"{process} envoie {ratio:F1}x la moyenne habituelle", ip, process));
			}
			else if (ratio >= 3)
			{
				alerts.Add(CreateAlert(AlertType.VolumeAnomaly, RiskLevel.Medium, "Volume superieur a l'historique",
					$"Transfert {ratio:F1}x superieur a la moyenne", ip, process));
			}
		}

		if (snapshot is { WindowBytes: > 200_000_000 })
		{
			alerts.Add(CreateAlert(AlertType.VolumeAnomaly, RiskLevel.High, "Debit cumule eleve",
				$"{snapshot.Value.WindowBytes / 1_000_000d:F1} MB envoyes sur 15 min", ip, process));
		}
	}

	private static void AnalyzeBursts(DestinationSnapshot? snapshot, string ip, string process, int port, List<SecurityAlert> alerts)
	{
		if (snapshot is null)
		{
			return;
		}

		if (snapshot.Value.Connections30s >= 20)
		{
			alerts.Add(CreateAlert(AlertType.RapidConnections, RiskLevel.High, "Connexions rapides suspectes",
				$"{snapshot.Value.Connections30s} connexions vers {ip} en 30s", ip, process));
		}
		else if (snapshot.Value.Connections30s >= 10)
		{
			alerts.Add(CreateAlert(AlertType.RapidConnections, RiskLevel.Medium, "Burst de connexions",
				$"{snapshot.Value.Connections30s} tentatives recentes sur le port {port}", ip, process));
		}

		if (snapshot.Value.Connections5Min >= 200)
		{
			alerts.Add(CreateAlert(AlertType.PortScanning, RiskLevel.High, "Activite type scan",
				$"{snapshot.Value.Connections5Min} connexions en 5 min", ip, process));
		}
	}

	private static void AnalyzeNewOrDormantDestination(
		DestinationSnapshot? snapshot,
		string ip,
		string process,
		int port,
		long bytesOut,
		DateTime connectionTime,
		List<SecurityAlert> alerts)
	{
		if (snapshot is null)
		{
			if (bytesOut > 5_000_000)
			{
				alerts.Add(CreateAlert(AlertType.UnknownDestination, RiskLevel.Medium, "Nouvelle destination avec fort volume",
					$"Premiere communication significative vers {ip}", ip, process));
			}
			else
			{
				alerts.Add(CreateAlert(AlertType.UnknownDestination, RiskLevel.Low, "Nouvelle destination",
					$"Premiere communication observee vers {ip}:{port}", ip, process));
			}
			return;
		}

		if (snapshot.Value.TotalConnections <= 3 && bytesOut > 2_000_000)
		{
			alerts.Add(CreateAlert(AlertType.UnknownDestination, RiskLevel.Medium, "Destination peu frequentee",
				$"Seulement {snapshot.Value.TotalConnections} connexions historiques", ip, process));
		}

		if ((connectionTime - snapshot.Value.LastSeen) > DormantWindow && bytesOut > 1_000_000)
		{
			alerts.Add(CreateAlert(AlertType.UnknownDestination, RiskLevel.Medium, "Reactivation inattendue",
				$"Aucune activite depuis {snapshot.Value.LastSeen:g}", ip, process));
		}

		if (snapshot.Value.TotalConnections >= 5 &&
			!snapshot.Value.Processes.Any(p => p.Equals(process, StringComparison.OrdinalIgnoreCase)))
		{
			alerts.Add(CreateAlert(AlertType.SuspiciousProcess, RiskLevel.Low, "Nouveau processus pour cette IP",
				$"{process} n'a jamais contacte {ip}", ip, process));
		}
	}

	private static void AnalyzeProcess(string processName, string ip, long bytesOut, DestinationSnapshot? snapshot, List<SecurityAlert> alerts)
	{
		if (IsSuspiciousProcess(processName))
		{
			alerts.Add(CreateAlert(AlertType.SuspiciousProcess, RiskLevel.Medium, "Processus potentiellement compromis",
				$"{processName} communique avec {ip}", ip, processName));
		}

		if (IsSystemProcess(processName) && bytesOut > 10_000_000)
		{
			alerts.Add(CreateAlert(AlertType.SuspiciousProcess, RiskLevel.High, "Processus systeme inhabituel",
				$"{processName} exfiltre {bytesOut / 1_000_000d:F1} MB", ip, processName));
		}

		if (snapshot is { TotalConnections: >= 10, Processes: { } processes } &&
			processes.Count >= 3 &&
			processes.Any(p => p.Equals("unknown", StringComparison.OrdinalIgnoreCase)))
		{
			alerts.Add(CreateAlert(AlertType.SuspiciousProcess, RiskLevel.Low, "Destination frequentee par processus inconnus",
				"Plusieurs processus inconnus joignent cette IP", ip, processName));
		}
	}

	private static void AnalyzePorts(int port, string ip, string process, List<SecurityAlert> alerts)
	{
		if (SuspiciousPorts.Contains(port))
		{
			alerts.Add(CreateAlert(AlertType.PortScanning, RiskLevel.High, "Port historiquement malveillant",
				$"Flux sortant detecte sur le port {port}", ip, process));
		}
		else if (DangerousPorts.Contains(port))
		{
			alerts.Add(CreateAlert(AlertType.PortScanning, RiskLevel.Medium, "Port potentiellement dangereux",
				$"Connexion sortante sur {port}", ip, process));
		}
	}

	private static void AnalyzeAfterHours(DateTime timestamp, long bytesOut, string ip, string process, List<SecurityAlert> alerts)
	{
		if (!IsAfterHours(timestamp))
		{
			return;
		}

		if (bytesOut > 1_000_000)
		{
			alerts.Add(CreateAlert(AlertType.UnknownDestination, RiskLevel.Low, "Activite hors horaires",
				$"Transfert nocturne de {bytesOut / 1_000_000d:F1} MB vers {ip}", ip, process));
		}
	}

	private static bool IsAfterHours(DateTime timestamp)
		=> timestamp.Hour < 6 || timestamp.Hour >= 22;

	private static bool IsSuspiciousProcess(string processName)
	{
		if (string.IsNullOrWhiteSpace(processName))
		{
			return true;
		}

		var lowered = processName.ToLowerInvariant();
		return SuspiciousProcessTokens.Any(lowered.Contains);
	}

	private static bool IsSystemProcess(string processName)
		=> processName.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)
		   || processName.Equals("services.exe", StringComparison.OrdinalIgnoreCase)
		   || processName.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase)
		   || processName.Equals("winlogon.exe", StringComparison.OrdinalIgnoreCase);

	private static SecurityAlert CreateAlert(AlertType type, RiskLevel severity, string title, string description, string ip, string process)
		=> new(type, severity, title, description, DateTime.UtcNow, ip, process);

	private readonly struct DestinationSnapshot
	{
		public DestinationSnapshot(double averageBytes, long windowBytes, int totalConnections, DateTime firstSeen, DateTime lastSeen, int connections5Min, int connections30s, IReadOnlyCollection<int> ports, IReadOnlyCollection<string> processes)
		{
			AverageBytes = averageBytes;
			WindowBytes = windowBytes;
			TotalConnections = totalConnections;
			FirstSeen = firstSeen;
			LastSeen = lastSeen;
			Connections5Min = connections5Min;
			Connections30s = connections30s;
			Ports = ports;
			Processes = processes;
		}

		public double AverageBytes { get; }
		public long WindowBytes { get; }
		public int TotalConnections { get; }
		public DateTime FirstSeen { get; }
		public DateTime LastSeen { get; }
		public int Connections5Min { get; }
		public int Connections30s { get; }
		public IReadOnlyCollection<int> Ports { get; }
		public IReadOnlyCollection<string> Processes { get; }
	}

	private sealed class DestinationStats
	{
		private readonly object _gate = new();
		private readonly LinkedList<DateTime> _connections = new();
		private readonly LinkedList<(DateTime Timestamp, long Bytes)> _volumeWindow = new();
		private readonly HashSet<int> _ports = new();
		private readonly HashSet<string> _processes = new(StringComparer.OrdinalIgnoreCase);
		private long _windowBytes;

		public DestinationStats(DateTime timestamp)
		{
			FirstSeen = timestamp;
			LastSeen = timestamp;
		}

		public long TotalBytes { get; private set; }
		public int TotalConnections { get; private set; }
		public DateTime FirstSeen { get; private set; }
		public DateTime LastSeen { get; private set; }

		public void AddSample(string processName, int port, long bytes, DateTime timestamp)
		{
			lock (_gate)
			{
				if (FirstSeen == default)
				{
					FirstSeen = timestamp;
				}

				LastSeen = timestamp;
				TotalConnections++;
				TotalBytes += bytes;
				_ports.Add(port);
				_processes.Add(processName);

				_connections.AddLast(timestamp);
				_volumeWindow.AddLast((timestamp, bytes));
				_windowBytes += bytes;

				Trim(timestamp);
			}
		}

		public DestinationSnapshot Snapshot(DateTime reference)
		{
			lock (_gate)
			{
				Trim(reference);

				var recentCut = reference - RecentWindow;
				var burstCut = reference - BurstWindow;
				var connections5Min = _connections.Count(ts => ts >= recentCut);
				var connections30s = _connections.Count(ts => ts >= burstCut);

				var avg = TotalConnections == 0 ? 0 : (double)TotalBytes / TotalConnections;

				return new DestinationSnapshot(
					avg,
					_windowBytes,
					TotalConnections,
					FirstSeen,
					LastSeen,
					connections5Min,
					connections30s,
					_ports.ToArray(),
					_processes.ToArray());
			}
		}

		private void Trim(DateTime reference)
		{
			var cutoff = reference - HistoryWindow;

			while (_connections.First is { Value: var ts } && ts < cutoff)
			{
				_connections.RemoveFirst();
			}

			while (_volumeWindow.First is { Value: var entry } && entry.Timestamp < cutoff)
			{
				_windowBytes -= entry.Bytes;
				_volumeWindow.RemoveFirst();
			}
		}
	}
}
