# Smart Network Traffic Analyzer — Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — 2026-04-12

### Added
- **Full CI/CD pipeline** — GitHub Actions for build, test, security scan, lint, and CodeQL
- **Release workflow** — Tag-based release with auto-publish
- **Unit test projects** — `App.Core.Tests` and `App.Infrastructure.Tests` with xUnit
- **`.editorconfig`** — Consistent coding style enforcement
- **`CHANGELOG.md`** — This file
- **Security analysis integration** — `ISecurityAnalysisService` now wired into ViewModel
- **IP categorization service** — `IIPCategorizationService` properly implements interface
- **Security scoring service** — `ISecurityScoringService` with factor breakdown
- **Anomaly detection service** — `IAnomalyDetectionService` with rapid-connection detection
- **Security columns in DataGrid** — Category, Score, Risk display
- **Monitoring status indicator** — Green dot + connection count in header

### Changed
- **MAJOR: Solution file** — Added Core, Infrastructure, and both test projects
- **REFACTORED: All services** — Proper DI with `ILoggingService` injected everywhere
- **REFACTORED: AggregatedReputationService** — No more empty catch blocks, proper error logging
- **REFACTORED: BlocklistReputationService** — Extracted `CidrMatcher` utility, validation, logging
- **REFACTORED: IpApiGeoService** — Accepts `HttpClient` + `ILoggingService` via DI
- **REFACTORED: OllamaAnalysisService** — Accepts `ILoggingService`, proper cancellation handling
- **REFACTORED: MainViewModel** — Full DI constructor, `IDisposable`, `ISecurityAnalysisService` integration
- **REFACTORED: ConnectionItem** — Added `SecurityScore`, `SecurityCategory`, `RiskDisplay`
- **REFACTORED: MainWindow.xaml** — New columns, header status bar, styled resources
- **REFACTORED: App.xaml.cs** — Complete DI registration for all services including security
- **REMOVED: `Class1.cs`** phantom files from Core and Infrastructure

### Fixed
- Empty `catch { }` blocks → proper logging with `ILoggingService`
- `Console.WriteLine` debug statements → structured logging
- Missing argument validation → `ArgumentException.ThrowIfNullOrWhiteSpace`
- Security interfaces defined but never implemented → full implementations
- ViewModel resolving services directly → proper DI injection
- No test coverage → 40+ unit tests covering all services