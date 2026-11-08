# Changelog

All notable changes to RepoGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-08

### Added
- **Core Scanning Engine**:
  - `RepoScanner` with error-isolated analyzer execution.
  - Deterministic finding deduplication via content-based SHA-256 fingerprinting.
  - Safe repository context (`ScanContext`) with traversal protection and file size caps.
- **Built-in Analyzers**:
  - `DocumentationAnalyzer`: README existence, installation/usage sections, LICENSE, CONTRIBUTING.
  - `DependencyAnalyzer`: unpinned dependencies, OSV API CVE/GHSA scanning, registry version checks.
  - `SecurityAnalyzer`: secret detection (AWS keys, GitHub tokens, Slack webhooks, private keys), dangerous calls (`shell=True`, `eval`), secret masking.
  - `TestingAnalyzer`: test directory detection, framework identification, CI test step verification.
  - `CodeQualityAnalyzer`: Python AST cyclomatic complexity, parameter counts, function length, wildcard imports.
  - `CiCdAnalyzer`: GitHub workflow validation, permissions auditing (`write-all`), mutable branch pinning.
- **Health Scoring Engine**:
  - Transparent 0-100 scoring with letter grades (`A` to `F`).
  - Configurable category weights and severity deductions.
  - Category breakdown and explicit reporting of unavailable checks.
- **Multi-Format Reporting**:
  - Interactive Rich terminal report with styled tables and panels.
  - Machine-readable JSON output conforming to documented schema.
  - GitHub-Flavored Markdown report with Shields.io badges.
- **Extensible Plugin System**:
  - `BaseAnalyzer` standard interface.
  - Dynamic discovery via Python entry points (`repoguard.plugins`).
  - Example Docker security plugin in `examples/custom_plugin/`.
- **CI/CD Integration**:
  - Reusable composite GitHub Action (`action.yml`).
  - Automated step summary, PR annotations, and report artifact uploads.
- **CLI Commands**:
  - `repoguard scan [PATH]`
  - `repoguard version`
  - `repoguard config init`
  - `repoguard plugins list` & `repoguard plugins info`
