using System.ComponentModel;

namespace SmartNetworkTrafficAnalyzer.UI.Resources;

/// <summary>
/// Localization singleton — English by default, French toggle.
/// Bind in XAML via {Binding Source={x:Static res:Loc.I}, Path=PropertyName}
/// </summary>
public sealed class Loc : INotifyPropertyChanged
{
    public static Loc I { get; } = new();

    private string _lang = "en";

    public string Language
    {
        get => _lang;
        set
        {
            if (_lang == value) return;
            _lang = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
        }
    }

    private bool Fr => _lang == "fr";

    // ── App ──
    public string AppTitle => Fr ? "🔍 Analyseur Réseau Intelligent" : "🔍 Smart Network Traffic Analyzer";
    public string ConnectionsUnit => Fr ? "connexions" : "connections";

    // ── Toolbar ──
    public string SearchPlaceholder => Fr ? "Rechercher (IP, processus, hôte, pays)..." : "Search (IP, process, host, country)...";
    public string SummaryBtn => Fr ? "📊 Résumé" : "📊 Summary";
    public string LanguageLabel => Fr ? "🇫🇷 FR" : "🇬🇧 EN";

    // ── Grid Headers ──
    public string HdrFirstSeen => Fr ? "Vu à" : "Seen";
    public string HdrDir => "Dir";
    public string HdrRemoteIp => Fr ? "IP Distante" : "Remote IP";
    public string HdrHostname => Fr ? "Hôte" : "Hostname";
    public string HdrCountry => Fr ? "Pays" : "Country";
    public string HdrPort => "Port";
    public string HdrRisk => Fr ? "Risque" : "Risk";
    public string HdrCategory => Fr ? "Catégorie" : "Category";
    public string HdrScore => "Score";
    public string HdrProcess => Fr ? "Processus" : "Process";

    // ── Right Panel ──
    public string OllamaModel => Fr ? "🤖 Modèle Ollama" : "🤖 Ollama Model";
    public string ModelHint => Fr
        ? "Le modèle sélectionné est utilisé pour les nouvelles analyses."
        : "Selected model is used for new analyses.";
    public string ConnectionDetails => Fr ? "📋 Détails Connexion" : "📋 Connection Details";
    public string AiAnalysis => Fr ? "🤖 Analyse IA Approfondie" : "🤖 Deep AI Analysis";
    public string ReanalyzeBtn => Fr ? "🔄 Réanalyser" : "🔄 Reanalyze";
    public string ScanIpBtn => Fr ? "🔎 Scanner IP" : "🔎 Scan IP";
    public string IpScanTitle => Fr ? "🔎 Résultat Scan IP" : "🔎 IP Scan Result";

    // ── Context Menu ──
    public string CopyIp => Fr ? "📋 Copier l'IP" : "📋 Copy IP";
    public string CopyHostname => Fr ? "📋 Copier le hostname" : "📋 Copy Hostname";
    public string CopyProcessName => Fr ? "📋 Copier le nom du processus" : "📋 Copy Process Name";
    public string CopyPid => Fr ? "📋 Copier le PID" : "📋 Copy PID";

    // ── Status ──
    public string LoadingModels => Fr ? "Chargement des modèles..." : "Loading models...";
    public string ModelsAvailableFmt => Fr ? "{0} modèle(s) disponible(s)" : "{0} model(s) available";
    public string AnalyzingWithFmt => Fr ? "Analyse en cours avec {0}..." : "Analyzing with {0}...";
    public string EmptyAnalysis => Fr
        ? "⚠️ L'analyse Ollama est vide. Essayez de changer de modèle."
        : "⚠️ Ollama analysis is empty. Try changing the model.";
    public string ScanningIp => Fr ? "Scan de l'IP en cours..." : "Scanning IP...";

    // ── Summary ──
    public string SummaryTitle => Fr ? "📊 Résumé Global" : "📊 Global Summary";
    public string TotalConnections => Fr ? "Connexions totales" : "Total Connections";
    public string UniqueIps => Fr ? "IPs uniques" : "Unique IPs";
    public string UniqueProcesses => Fr ? "Processus uniques" : "Unique Processes";
    public string Countries => Fr ? "Pays" : "Countries";
    public string TopProcesses => Fr ? "Top Processus" : "Top Processes";
    public string TopCountries => Fr ? "Top Pays" : "Top Countries";
    public string TopIps => Fr ? "Top IPs" : "Top IPs";
    public string HighRisk => Fr ? "Connexions haut risque" : "High Risk Connections";

    // ── Detail labels ──
    public string LblIp => "🌐 IP:";
    public string LblHost => "🏠 Host:";
    public string LblCountry => Fr ? "🌍 Pays:" : "🌍 Country:";
    public string LblProcess => "⚙️ Process:";
    public string LblRisk => Fr ? "⚠️ Risque:" : "⚠️ Risk:";
    public string LblCategory => Fr ? "🏷️ Cat:" : "🏷️ Cat:";
    public string LblScore => "📊 Score:";
    public string LblIsp => "ISP:";
    public string LblOrg => Fr ? "Organisation:" : "Organization:";
    public string LblDomain => Fr ? "Domaine:" : "Domain:";
    public string LblCity => Fr ? "Ville:" : "City:";
    public string LblRegion => Fr ? "Région:" : "Region:";
    public string LblTimezone => Fr ? "Fuseau:" : "Timezone:";

    // ── Process detail labels ──
    public string ProcessDetails => Fr ? "📂 Détails Processus" : "📂 Process Details";
    public string LblPath => Fr ? "📂 Chemin:" : "📂 Path:";
    public string LblDescription => "📝 Description:";
    public string LblPublisher => Fr ? "🏢 Éditeur:" : "🏢 Publisher:";
    public string LblWindowTitle => Fr ? "🪟 Fenêtre:" : "🪟 Window:";
    public string LblPid => "🔢 PID:";
    public string NoProcessDetails => Fr ? "Sélectionnez une connexion" : "Select a connection";

    // ── Errors ──
    public string OllamaTimeout => Fr
        ? "⏱️ Timeout: L'analyse prend trop de temps."
        : "⏱️ Timeout: Analysis taking too long.";
    public string OllamaUnavailable => Fr
        ? "🔌 Ollama non disponible."
        : "🔌 Ollama unavailable.";

    public event PropertyChangedEventHandler? PropertyChanged;
}
