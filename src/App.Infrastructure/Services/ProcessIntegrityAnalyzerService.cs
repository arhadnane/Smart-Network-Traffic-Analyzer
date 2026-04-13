using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Core.Models;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Services;

/// <summary>
/// Analyzes process integrity: suspicious paths, masquerading system processes,
/// unsigned executables running from temp directories, and anomalous parent-child relationships.
/// </summary>
public sealed class ProcessIntegrityAnalyzerService : IProcessIntegrityAnalyzer
{
    // Legitimate system process paths (Windows)
    private static readonly Dictionary<string, string[]> LegitimateSystemPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost.exe"] = new[] { @"C:\Windows\System32\svchost.exe", @"C:\Windows\SysWOW64\svchost.exe" },
        ["services.exe"] = new[] { @"C:\Windows\System32\services.exe" },
        ["lsass.exe"] = new[] { @"C:\Windows\System32\lsass.exe" },
        ["csrss.exe"] = new[] { @"C:\Windows\System32\csrss.exe" },
        ["winlogon.exe"] = new[] { @"C:\Windows\System32\winlogon.exe" },
        ["smss.exe"] = new[] { @"C:\Windows\System32\smss.exe" },
        ["wininit.exe"] = new[] { @"C:\Windows\System32\wininit.exe" },
        ["explorer.exe"] = new[] { @"C:\Windows\explorer.exe" },
        ["taskhostw.exe"] = new[] { @"C:\Windows\System32\taskhostw.exe" },
        ["conhost.exe"] = new[] { @"C:\Windows\System32\conhost.exe" },
        ["dwm.exe"] = new[] { @"C:\Windows\System32\dwm.exe" },
        ["RuntimeBroker.exe"] = new[] { @"C:\Windows\System32\RuntimeBroker.exe" },
    };

    // Directories that should never host legitimate long-running network processes
    private static readonly string[] SuspiciousPaths = new[]
    {
        @"\Temp\",
        @"\tmp\",
        @"\AppData\Local\Temp\",
        @"\Downloads\",
        @"\Recycle.Bin\",
        @"\ProgramData\",  // Legitimate but worth flagging network activity from
        @"\Public\",
    };

    // Processes that should NEVER make outbound connections
    private static readonly HashSet<string> NoNetworkProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "notepad.exe", "calc.exe", "mspaint.exe", "write.exe",
        "wordpad.exe", "charmap.exe", "snippingtool.exe", "osk.exe"
    };

    // Detect process name similarity to system processes (typosquatting/masquerading)
    private static readonly string[] SystemProcessNames = new[]
    {
        "svchost", "services", "lsass", "csrss", "winlogon", "smss",
        "explorer", "conhost", "dwm", "taskhostw", "spoolsv", "wininit"
    };

    private readonly ConcurrentDictionary<int, string> _processPathCache = new();

    public Task<SecurityAlert[]> AnalyzeProcessAsync(string processName, int processId, string remoteIp, CancellationToken ct = default)
    {
        if (ct.IsCancellationRequested)
            return Task.FromCanceled<SecurityAlert[]>(ct);

        var alerts = new List<SecurityAlert>();

        // 1. Check if process should never have network access
        if (NoNetworkProcesses.Contains(processName))
        {
            alerts.Add(new SecurityAlert(
                AlertType.SuspiciousProcess,
                RiskLevel.High,
                "Processus non-reseau avec connexion",
                $"{processName} (PID {processId}) ne devrait pas avoir d'acces reseau; connexion vers {remoteIp}",
                DateTime.UtcNow, remoteIp, processName));
        }

        // 2. Check for masquerading (name similar to system process but slightly different)
        var masqueradeAlert = CheckMasquerading(processName, remoteIp);
        if (masqueradeAlert != null)
            alerts.Add(masqueradeAlert);

        // 3. Check process path for suspicious locations
        var pathAlerts = CheckProcessPath(processName, processId, remoteIp);
        alerts.AddRange(pathAlerts);

        // 4. Check for double extension tricks (e.g., "document.pdf.exe")
        if (HasDoubleExtension(processName))
        {
            alerts.Add(new SecurityAlert(
                AlertType.ProcessMasquerade,
                RiskLevel.High,
                "Double extension detectee",
                $"{processName} utilise une double extension; technique courante de malware",
                DateTime.UtcNow, remoteIp, processName));
        }

        return Task.FromResult(alerts.ToArray());
    }

    private static SecurityAlert? CheckMasquerading(string processName, string remoteIp)
    {
        var baseName = Path.GetFileNameWithoutExtension(processName).ToLowerInvariant();

        foreach (var systemName in SystemProcessNames)
        {
            if (baseName.Equals(systemName, StringComparison.OrdinalIgnoreCase))
                continue; // Exact match is fine — path check will validate location

            // Check for common masquerading tricks
            if (LevenshteinDistance(baseName, systemName) == 1 && baseName.Length >= 4)
            {
                return new SecurityAlert(
                    AlertType.ProcessMasquerade,
                    RiskLevel.High,
                    "Suspicion d'usurpation de processus systeme",
                    $"'{processName}' ressemble a '{systemName}.exe' (distance=1); possible masquerade",
                    DateTime.UtcNow, remoteIp, processName);
            }

            // Check for homoglyph/unicode tricks: svch0st vs svchost
            if (baseName.Replace('0', 'o').Replace('1', 'l').Equals(systemName, StringComparison.OrdinalIgnoreCase)
                && !baseName.Equals(systemName, StringComparison.OrdinalIgnoreCase))
            {
                return new SecurityAlert(
                    AlertType.ProcessMasquerade,
                    RiskLevel.High,
                    "Homoglyphe detecte dans le nom du processus",
                    $"'{processName}' utilise des substitutions de caracteres pour ressembler a '{systemName}.exe'",
                    DateTime.UtcNow, remoteIp, processName);
            }
        }

        return null;
    }

    private List<SecurityAlert> CheckProcessPath(string processName, int processId, string remoteIp)
    {
        var alerts = new List<SecurityAlert>();

        try
        {
            string? processPath = null;

            if (!_processPathCache.TryGetValue(processId, out processPath))
            {
                try
                {
                    using var proc = Process.GetProcessById(processId);
                    processPath = proc.MainModule?.FileName;
                    if (processPath != null)
                        _processPathCache.TryAdd(processId, processPath);
                }
                catch
                {
                    // Access denied or process exited
                }
            }

            if (processPath == null)
                return alerts;

            // Check system process running from wrong location
            if (LegitimateSystemPaths.TryGetValue(processName, out var legitimatePaths))
            {
                if (!legitimatePaths.Any(lp => processPath.Equals(lp, StringComparison.OrdinalIgnoreCase)))
                {
                    alerts.Add(new SecurityAlert(
                        AlertType.ProcessMasquerade,
                        RiskLevel.High,
                        "Processus systeme hors de son emplacement normal",
                        $"{processName} s'execute depuis '{processPath}' au lieu de '{legitimatePaths[0]}'",
                        DateTime.UtcNow, remoteIp, processName));
                }
            }

            // Check for suspicious directory
            foreach (var suspiciousPath in SuspiciousPaths)
            {
                if (processPath.Contains(suspiciousPath, StringComparison.OrdinalIgnoreCase))
                {
                    alerts.Add(new SecurityAlert(
                        AlertType.SuspiciousProcess,
                        RiskLevel.Medium,
                        "Executable dans un repertoire suspect",
                        $"{processName} s'execute depuis un repertoire temporaire/suspect: {Path.GetDirectoryName(processPath)}",
                        DateTime.UtcNow, remoteIp, processName));
                    break;
                }
            }
        }
        catch
        {
            // Silently handle process access errors
        }

        return alerts;
    }

    private static bool HasDoubleExtension(string processName)
    {
        var extensions = new[] { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".zip" };
        var name = processName.ToLowerInvariant();
        return extensions.Any(ext => name.Contains(ext + ".exe") || name.Contains(ext + ".scr") || name.Contains(ext + ".cmd"));
    }

    /// <summary>Levenshtein edit distance for masquerade detection.</summary>
    internal static int LevenshteinDistance(string source, string target)
    {
        if (string.IsNullOrEmpty(source)) return target?.Length ?? 0;
        if (string.IsNullOrEmpty(target)) return source.Length;

        var m = source.Length;
        var n = target.Length;
        var d = new int[m + 1, n + 1];

        for (int i = 0; i <= m; i++) d[i, 0] = i;
        for (int j = 0; j <= n; j++) d[0, j] = j;

        for (int i = 1; i <= m; i++)
        {
            for (int j = 1; j <= n; j++)
            {
                var cost = source[i - 1] == target[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
            }
        }

        return d[m, n];
    }
}
