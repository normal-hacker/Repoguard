# 🛡️ RepoGuard

> **Analyze. Detect. Improve.**

RepoGuard is an extensible, open-source repository health analyzer built for software engineers, open-source maintainers, and CI/CD pipelines.

RepoGuard scans codebases to evaluate documentation completeness, dependency security and freshness, exposed secrets, code maintainability, test coverage indicators, and CI/CD workflow security — calculating a transparent, deterministic health score from 0 to 100 with actionable remediation guidance.

[![CI](https://github.com/repoguard/repoguard/actions/workflows/ci.yml/badge.svg)](https://github.com/repoguard/repoguard/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

---

## Key Features

- 🔍 **Comprehensive Static Analysis**: 6 independent built-in analyzers covering Documentation, Dependencies, Security, Testing, Code Quality, and CI/CD.
- 🔒 **Security Invariants**: Never executes repository code; masks all detected secrets; prevents path traversal; supports offline scanning (`--no-network`).
- 📊 **Transparent Health Scoring Engine**: 0–100 health score with letter grades (`A`–`F`), category breakdown, and zero double-counting.
- 🔌 **Extensible Plugin Architecture**: Build independent custom analyzers using Python entry points (`repoguard.plugins`). Plugin crashes are isolated without stopping scans.
- 🤖 **GitHub Actions Integration**: Native reusable GitHub Action (`action.yml`) with Step Summary tables, PR annotations, and report artifact uploads.
- 📄 **Multi-Format Reporting**: Interactive Rich terminal reports, machine-readable JSON schemas, and GitHub-Flavored Markdown.

---

## Built-in Analyzers

| Category | Analyzer | What it Checks |
|---|---|---|
| **Documentation** | `documentation` | README presence, installation/usage instructions, LICENSE, CONTRIBUTING |
| **Dependencies** | `dependencies` | Unpinned versions, OSV API CVE/GHSA scanning, registry version checks |
| **Security** | `security` | AWS keys, GitHub tokens, Slack webhooks, private keys, `shell=True`, `eval()`, committed `.env` files |
| **Testing** | `testing` | Test directories, testing frameworks, CI automated test execution |
| **Code Quality** | `code_quality` | AST cyclomatic complexity, function length, parameter counts, wildcard imports |
| **CI/CD** | `cicd` | GitHub workflow presence, `permissions: write-all` auditing, mutable branch pinning (`@main`) |

---

## Installation

RepoGuard requires **Python 3.11 or later**. The recommended installation method on all platforms is **pipx**, which installs command-line applications in isolated environments.

### Windows

1. Install Python 3.11 or later from [python.org](https://www.python.org/downloads/windows/). During setup, enable **Add Python to PATH**.
2. Open Command Prompt or PowerShell and verify Python:

   ```cmd
   py --version
   ```

3. Install pipx:

   ```cmd
   py -m pip install --user pipx
   ```

4. Add pipx to PATH:

   ```cmd
   py -m pipx ensurepath
   ```

   Close and reopen the terminal after this step.

5. Install RepoGuard:

   ```cmd
   py -m pipx install repoguard-tool
   ```

6. Verify the installation:

   ```cmd
   repoguard version
   repoguard --help
   ```

### macOS and Linux

Install pipx using the instructions for your operating system at [pipx.pypa.io](https://pipx.pypa.io/stable/installation/), then run:

```bash
pipx install repoguard-tool
```

### Uninstall

To remove RepoGuard:

```bash
pipx uninstall repoguard-tool
```

---

## Quick Start

### 1. Scan a Repository

```bash
# Interactive terminal scan
repoguard scan .

# Generate JSON report
repoguard scan . --format json

# Generate Markdown report
repoguard scan . --format markdown --output report.md

# Offline scan (no external network lookups)
repoguard scan . --no-network

# Enforce quality gates (exit with code 1 if thresholds exceeded)
repoguard scan . --min-score 75 --fail-on high
```

### 2. Inspect Installed Plugins

```bash
repoguard plugins list
repoguard plugins info docker
```

### 3. Initialize Configuration File

```bash
repoguard config init
```

This generates a `.repoguard.yml` file with default scoring weights and thresholds.

---

## Health Scoring Methodology

RepoGuard calculates a deterministic score from 0 to 100 based on configured category weights:

- **Security**: 25%
- **Code Quality**: 25%
- **Documentation**: 15%
- **Dependencies**: 15%
- **Testing**: 10%
- **CI/CD**: 10%

Each category begins at **100 points**. Penalties are deducted based on unique finding severities:
- **Critical**: -25 pts
- **High**: -15 pts
- **Medium**: -8 pts
- **Low**: -3 pts
- **Info**: 0 pts

Scores are clamped to `[0, 100]` and mapped to grades (`A`: >=90, `B`: 80–89, `C`: 70–79, `D`: 60–69, `F`: <60).

> **Disclaimer**: The RepoGuard Health Score is an automated project-maintenance indicator. It is **NOT** a guarantee or warranty of security.

---

## GitHub Actions CI/CD Integration

Add RepoGuard to your GitHub repository by creating `.github/workflows/repoguard.yml`:

```yaml
name: RepoGuard Health Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: repoguard/repoguard@v1
        with:
          min-score: "70"
          fail-on: "high"
```

---

## Documentation

- [Installation Guide](docs/installation.md)
- [Architecture & Design](docs/architecture.md)
- [Analyzers Reference](docs/analyzers.md)
- [Plugin Development Guide](docs/plugins.md)
- [GitHub Actions Integration](docs/github-actions.md)
- [Configuration Reference](docs/configuration.md)
- [Health Scoring Engine](docs/scoring.md)
- [Example Plugin](examples/custom_plugin/README.md)

---

## Contributing

Contributions are warmly welcomed! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

RepoGuard is licensed under the [MIT License](LICENSE).
