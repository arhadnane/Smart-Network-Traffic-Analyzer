# Contributing to Smart Network Traffic Analyzer

Thank you for your interest in contributing! Here are the guidelines:

## Development Setup

1. **Prerequisites**: .NET 8.0 SDK, Windows 10/11
2. **Clone & restore**: `dotnet restore SmartNetworkTrafficAnalyzer.sln`
3. **Build**: `dotnet build SmartNetworkTrafficAnalyzer.sln -c Debug`
4. **Test**: `dotnet test SmartNetworkTrafficAnalyzer.sln`

## Code Style

- This project uses `.editorconfig` for consistent formatting
- Run `dotnet format` before committing
- All public APIs must have XML doc comments
- `TreatWarningsAsErrors` is enabled — no warnings in CI

## Architecture

```
App.Core          → Domain models & interfaces (no dependencies)
App.Infrastructure → Service implementations (depends on Core)
App.UI            → WPF presentation (depends on Core + Infrastructure)
App.Core.Tests    → Unit tests for Core
App.Infrastructure.Tests → Unit tests for Infrastructure
```

- **Dependencies flow inward**: UI → Infrastructure → Core
- **Never reference Infrastructure from Core**
- Use DI for all service resolution

## Pull Requests

1. Create a feature branch from `develop/**`
2. Add tests for any new functionality
3. Ensure all tests pass: `dotnet test`
4. Run format check: `dotnet format --verify-no-changes`
5. Open a PR against `main` or the appropriate develop branch

## Commit Messages

Use conventional commits:
- `feat: add IPv6 support`
- `fix: resolve CIDR matching for /0 networks`
- `refactor: extract CidrMatcher utility`
- `test: add BlocklistReputationService tests`
- `ci: add CodeQL workflow`
- `docs: update architecture diagram`