using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Lightweight threat-intel lookup with baked-in feeds, CIDR rules, and short-lived caching.
/// </summary>
public sealed class ThreatIntelligenceServices : IThreatIntelligenceService
{
	private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(30);
	private static readonly (string Prefix, string Description)[] SuspiciousPrefixes =
	{
		("185.220.", "Tor exit network (AbuseIPDB)"),
		("45.142.", "Bulletproof hosting linked to botnets"),
		("103.224.", "Malware distribution network"),
		("198.98.", "Known C2 infrastructure"),
		("23.129.", "Onion relay/VPN provider"),
		("37.120.", "High-risk VPN/proxy ASN"),
		("89.187.", "Commercial anonymizing VPN range")
	};

	private static readonly Dictionary<string, string> ExactIndicators = new(StringComparer.Ordinal)
	{
		["185.220.100.240"] = "Tor exit node flagged high-abuse (AbuseIPDB)",
		["45.142.214.191"] = "Botnet C2 server observed (VirusTotal)",
		["103.224.182.251"] = "Malware distribution IP (multiple AV engines)",
		["198.98.51.189"] = "Command & control server (EmergingThreats)",
		["94.102.49.190"] = "Previously compromised host (AbuseIPDB)",
		["195.123.234.154"] = "Ransomware dropper CDN"
	};

	private static readonly CidrRule[] CidrIndicators =
	{
		new("185.220.100.0/22", "Tor exit cluster (TheTorProject)"),
		new("45.155.205.0/24", "Known malware hosting (ThreatFox)"),
		new("104.244.72.0/21", "Onion routing infrastructure"),
		new("89.248.160.0/19", "Spamhaus DROP listed range"),
		new("156.146.32.0/22", "Residential-proxy botnet")
	};

	private static readonly string[] BogonPrefixes =
	{
		"0.", "10.", "100.64.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
		"172.28.", "172.29.", "172.30.", "172.31.", "192.0.0.", "192.168.", "198.18.", "198.51.100.",
		"203.0.113."
	};

	private static readonly string[] KnownGoodPrefixes =
	{
		"8.8.", "1.1.", "9.9.9.", "208.67.", "151.101.", "199.232."
	};

	private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);

	public Task<string?> LookupAsync(string ipAddress, CancellationToken ct = default)
	{
		if (ct.IsCancellationRequested)
		{
			return Task.FromCanceled<string?>(ct);
		}

		if (string.IsNullOrWhiteSpace(ipAddress))
		{
			return Task.FromResult<string?>(null);
		}

		var now = DateTime.UtcNow;
		if (_cache.TryGetValue(ipAddress, out var cached) && cached.Expiration > now)
		{
			return Task.FromResult(cached.Value);
		}

		if (!IPAddress.TryParse(ipAddress, out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
		{
			var result = "Adresse IP non valide ou IPv6 non supportee";
			_cache[ipAddress] = new CacheEntry(result, now + CacheDuration);
			return Task.FromResult<string?>(result);
		}

		var evaluation = EvaluateIndicators(ipAddress, address);
		_cache[ipAddress] = new CacheEntry(evaluation, now + CacheDuration);
		return Task.FromResult(evaluation);
	}

	private static string? EvaluateIndicators(string ipAddress, IPAddress address)
	{
		if (KnownGoodPrefixes.Any(prefix => ipAddress.StartsWith(prefix, StringComparison.Ordinal)))
		{
			return null;
		}

		var findings = new List<string>();

		if (ExactIndicators.TryGetValue(ipAddress, out var exact))
		{
			findings.Add(exact);
		}

		foreach (var (prefix, description) in SuspiciousPrefixes)
		{
			if (ipAddress.StartsWith(prefix, StringComparison.Ordinal))
			{
				findings.Add(description);
			}
		}

		foreach (var cidr in CidrIndicators)
		{
			if (cidr.Contains(address))
			{
				findings.Add(cidr.Description);
			}
		}

		if (BogonPrefixes.Any(prefix => ipAddress.StartsWith(prefix, StringComparison.Ordinal)))
		{
			findings.Add("Adresse privee/bogon observee sur une connexion externe");
		}

		if (address.GetAddressBytes()[0] is 45 or 156 && findings.Count == 0)
		{
			findings.Add("ASN a forte densite de proxies anonymes");
		}

		if (findings.Count == 0)
		{
			return null;
		}

		var distinct = findings.Distinct().ToArray();
		return distinct.Length == 1 ? distinct[0] : string.Join(" | ", distinct);
	}

	private sealed record CacheEntry(string? Value, DateTime Expiration);

	private readonly struct CidrRule
	{
		private readonly uint _network;
		private readonly uint _mask;
		public string Description { get; }

		public CidrRule(string cidr, string description)
		{
			var parts = cidr.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
			if (parts.Length != 2)
			{
				throw new ArgumentException($"CIDR invalide: {cidr}", nameof(cidr));
			}

			if (!IPAddress.TryParse(parts[0], out var network) || network.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
			{
				throw new ArgumentException($"Adresse CIDR non IPv4: {cidr}", nameof(cidr));
			}

			if (!int.TryParse(parts[1], out var prefix) || prefix is < 0 or > 32)
			{
				throw new ArgumentException($"Prefix CIDR invalide: {cidr}", nameof(cidr));
			}

			_network = ToUInt32(network) & PrefixToMask(prefix);
			_mask = PrefixToMask(prefix);
			Description = description;
		}

		public bool Contains(IPAddress address)
		{
			if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
			{
				return false;
			}

			var value = ToUInt32(address);
			return (value & _mask) == _network;
		}

		private static uint ToUInt32(IPAddress address)
		{
			var bytes = address.GetAddressBytes();
			if (BitConverter.IsLittleEndian)
			{
				Array.Reverse(bytes);
			}
			return BitConverter.ToUInt32(bytes, 0);
		}

		private static uint PrefixToMask(int prefix) => prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
	}
}
