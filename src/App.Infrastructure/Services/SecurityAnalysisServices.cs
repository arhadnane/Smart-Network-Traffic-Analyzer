using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Orchestrates the full security analysis pipeline including all detection services.
/// </summary>
public sealed class SimpleSecurityAnalysisService : ISecurityAnalysisService
{
	private readonly IIPCategorizationService _categorization;
	private readonly ISecurityScoringService _scoring;
	private readonly IAnomalyDetectionService _anomalyDetection;
	private readonly IThreatIntelligenceService _threatIntel;
	private readonly IBeaconingDetector _beaconing;
	private readonly IProcessIntegrityAnalyzer _processIntegrity;
	private readonly INetworkBaselineService _networkBaseline;
	private readonly IOpenThreatFeedService? _openThreatFeed;

	public SimpleSecurityAnalysisService(
		IIPCategorizationService categorization,
		ISecurityScoringService scoring,
		IAnomalyDetectionService anomalyDetection,
		IThreatIntelligenceService threatIntel,
		IBeaconingDetector beaconing,
		IProcessIntegrityAnalyzer processIntegrity,
		INetworkBaselineService networkBaseline,
		IOpenThreatFeedService? openThreatFeed = null)
	{
		_categorization = categorization;
		_scoring = scoring;
		_anomalyDetection = anomalyDetection;
		_threatIntel = threatIntel;
		_beaconing = beaconing;
		_processIntegrity = processIntegrity;
		_networkBaseline = networkBaseline;
		_openThreatFeed = openThreatFeed;
	}

	public async Task<SecurityAnalysisResult> AnalyzeConnectionAsync(
		string remoteIp,
		string processName,
		int port,
		long bytesOut,
		DateTime connectionTime,
		CancellationToken ct = default)
	{
		ct.ThrowIfCancellationRequested();

		// Phase 1: Categorize the IP
		var category = await _categorization.CategorizeAsync(remoteIp, ct).ConfigureAwait(false);

		// Phase 2: Record and detect anomalies (existing)
		_anomalyDetection.RecordConnection(remoteIp, processName, port, bytesOut, connectionTime);
		var anomalyAlerts = await _anomalyDetection.CheckAnomaliesAsync(remoteIp, processName, port, bytesOut, connectionTime, ct)
			.ConfigureAwait(false);

		// Phase 3: Record beaconing data and detect patterns
		_beaconing.RecordConnection(remoteIp, processName, connectionTime);
		var beaconingAlerts = await _beaconing.DetectBeaconingAsync(remoteIp, ct).ConfigureAwait(false);

		// Phase 4: Network baseline analysis
		_networkBaseline.RecordSample(processName, remoteIp, port, bytesOut, connectionTime);
		var baselineAlerts = await _networkBaseline.EvaluateAsync(processName, remoteIp, port, bytesOut, connectionTime, ct)
			.ConfigureAwait(false);

		// Phase 5: Process integrity analysis (PID 0 = unknown)
		var processAlerts = await _processIntegrity.AnalyzeProcessAsync(processName, 0, remoteIp, ct).ConfigureAwait(false);

		// Merge all alerts, deduplicate by type+title
		var allAlerts = anomalyAlerts
			.Concat(beaconingAlerts)
			.Concat(baselineAlerts)
			.Concat(processAlerts)
			.GroupBy(a => (a.Type, a.Title))
			.Select(g => g.OrderByDescending(a => a.Severity).First())
			.ToArray();

		// Phase 6: Score with category and all alerts
		var context = new SecurityScoringContext(remoteIp, processName, port, bytesOut);
		var score = await _scoring.CalculateScoreAsync(context, category, allAlerts, ct).ConfigureAwait(false);

		// Phase 7: Threat intelligence (local + open feeds)
		var threatIntel = await _threatIntel.LookupAsync(remoteIp, ct).ConfigureAwait(false);
		string? openFeedIntel = null;
		if (_openThreatFeed != null)
		{
			try
			{
				openFeedIntel = await _openThreatFeed.CheckIpAsync(remoteIp, ct).ConfigureAwait(false);
			}
			catch
			{
				// Non-critical: don't fail the analysis if the feed is down
			}
		}

		var combinedIntel = CombineIntel(threatIntel, openFeedIntel);
		var summary = BuildSummary(category, score, allAlerts, combinedIntel);

		return new SecurityAnalysisResult(category, score, allAlerts, summary, combinedIntel);
	}

	private static string? CombineIntel(string? local, string? openFeed)
	{
		if (string.IsNullOrWhiteSpace(local) && string.IsNullOrWhiteSpace(openFeed))
			return null;
		if (string.IsNullOrWhiteSpace(openFeed))
			return local;
		if (string.IsNullOrWhiteSpace(local))
			return openFeed;
		return $"{local} | {openFeed}";
	}

	private static string BuildSummary(IPCategory category, SecurityScore score, SecurityAlert[] alerts, string? threatIntel)
	{
		var severity = alerts.Length == 0 ? "Aucune alerte" : string.Join(", ", alerts.Select(a => a.Title));
		var intelPart = string.IsNullOrWhiteSpace(threatIntel) ? "Aucun renseignement connu" : threatIntel;
		return $"{category.Name} | Score {score.Value}/100 | {severity} | {intelPart}";
	}
}
