# Real-Time Network Traffic Analyzer – C# & XAML 🔍

> **Professional desktop application for monitoring, analyzing, and visualizing network traffic with security intelligence.**

A modern Windows desktop application built with **C# & WPF/XAML** that provides real-time network traffic monitoring, DNS resolution, IP reputation analysis, and geolocation intelligence. Features an interactive dashboard with live charts and comprehensive connection details.

![.NET 8](https://img.shields.io/badge/.NET-8.0-blue?style=flat-square&logo=dotnet)
![WPF](https://img.shields.io/badge/WPF-XAML-purple?style=flat-square)
![Architecture](https://img.shields.io/badge/Architecture-MVVM-green?style=flat-square)

## ✨ Key Features

### 🔄 Real-Time Monitoring
- **Live TCP Connection Tracking**: Monitors active network connections using Windows networking APIs
- **Process Information**: Identifies associated processes for each connection
- **Direction Analysis**: Distinguishes between inbound and outbound traffic
- **Bandwidth Visualization**: Real-time charts using OxyPlot library

### 🌐 Intelligence Enrichment
- **DNS Resolution**: Automatic reverse DNS lookups to identify hostnames
- **Geolocation**: Country and provider identification via ip-api.com
- **IP Reputation Analysis**: CIDR-based blocklist checking with extensible provider system
- **Risk Assessment**: Color-coded risk levels (Clean, Low, Medium, High, Malicious)

### 📊 Interactive Dashboard
- **Data Grid**: Sortable, filterable connection table with live updates
- **Live Charts**: Bandwidth monitoring with OxyPlot integration
- **Details Panel**: Selected connection enrichment (hostname, country, risk)
- **Professional UI**: Modern WPF interface with responsive design

### 🏗️ Enterprise Architecture
- **MVVM Pattern**: Clean separation of concerns with dependency injection
- **Modular Design**: Three-tier architecture (UI, Core, Infrastructure)
- **Extensible Services**: Plugin-ready reputation and geolocation providers
- **Async Operations**: Non-blocking UI with background enrichment

## 🏛️ Architecture Overview

```
src/
├── App.UI/                    # WPF Presentation Layer
│   ├── ViewModels/           # MVVM ViewModels with data binding
│   ├── Models/              # UI-specific models (ConnectionItem)
│   └── Views/               # XAML views and user controls
├── App.Core/                 # Business Logic & Abstractions
│   ├── Models/              # Domain models (Connection, Reputation, GeoInfo)
│   └── Abstractions/        # Service interfaces (IConnectionMonitor, IDnsResolver)
└── App.Infrastructure/       # External Services & Implementations
    ├── Services/            # Concrete implementations
    └── data/               # Blocklist files and configuration
```

### 🔧 Core Components

- **WindowsTcpConnectionMonitor**: Real-time TCP connection polling
- **SystemDnsResolver**: Windows DNS reverse lookup integration
- **IpApiGeoService**: HTTP-based geolocation service
- **BlocklistReputationService**: CIDR-based IP reputation checking
- **AggregatedReputationService**: Multi-provider risk aggregation

## 🚀 Quick Start

### Prerequisites
- Windows 10/11
- .NET 8.0 SDK
- Visual Studio Code (recommended)

### Build & Run

**Option 1: VS Code**
1. Open the workspace in VS Code
2. Press `F5` to launch with ".NET Launch App.UI"
3. Or run task "build:Release" → "run:UI"

**Option 2: Command Line**
```powershell
# Clone and navigate to project
cd "Smart Network Traffic Analyzer"

# Restore dependencies
dotnet restore SmartNetworkTrafficAnalyzer.sln

# Build solution
dotnet build SmartNetworkTrafficAnalyzer.sln -c Release

# Run application
dotnet run --project .\src\App.UI\App.UI.csproj
```

### 📋 Usage Instructions

1. **Launch the application** - The UI will start monitoring TCP connections automatically
2. **Generate traffic** - Open browsers, applications, or network tools
3. **Monitor connections** - View real-time connections in the main data grid
4. **Analyze enrichment** - Watch as DNS, geolocation, and reputation data populate
5. **Check security** - Review the Risk column for potential threats
6. **Select details** - Click any row to see enriched information in the details panel

## 🛡️ Security Features

### IP Reputation System
- **Offline Blocklists**: CIDR-based checking against local threat intelligence
- **Extensible Providers**: Ready for integration with APIs (AbuseIPDB, VirusTotal, etc.)
- **Risk Aggregation**: "Max-risk wins" algorithm across multiple sources
- **Performance Optimized**: Cached results with configurable TTL

### Threat Detection
- **Real-time Analysis**: Immediate reputation checking for new connections
- **Risk Visualization**: Color-coded risk levels in the interface
- **Historical Tracking**: Connection logging for forensic analysis

## 🔧 Configuration & Extensibility

### Adding Custom Blocklists
```
src/App.Infrastructure/data/blocklist.txt
```
Add CIDR ranges (one per line):
```
192.0.2.0/24
203.0.113.0/24
# Comments supported
```

### Extending Reputation Providers
Implement `IReputationService` for custom threat intelligence:
```csharp
public class CustomReputationService : IReputationService
{
    public async Task<Reputation> CheckAsync(string ip, CancellationToken ct)
    {
        // Your implementation
    }
}
```

## 📦 Dependencies

- **Microsoft.Extensions.DependencyInjection** - Service container
- **OxyPlot.Wpf** - Chart rendering for bandwidth visualization
- **System.Net.NetworkInformation** - Windows networking APIs

## 🎯 Roadmap

- [ ] Multi-language support (EN/FR)
- [ ] Advanced filtering and search
- [ ] Export functionality (CSV/JSON)
- [ ] Process-level analysis enhancement
- [ ] Additional chart types and metrics
- [ ] Settings persistence and configuration UI
- [ ] Online reputation API integrations

## 🤝 Contributing

This project follows clean architecture principles and MVVM patterns. Contributions welcome for:
- Additional reputation providers
- UI/UX improvements
- Performance optimizations
- Documentation enhancements

## 📄 License

Professional desktop application for network traffic analysis and security monitoring.

---

**Built with ❤️ using C# & WPF/XAML** | **Architecture: Clean MVVM with DI**
