# Analyzers Reference

RepoGuard provides 6 core built-in analyzers.

---

## 1. Documentation Analyzer (`documentation`)
Evaluates open-source documentation standards and discoverability.
- `DOC001`: Missing README file (High)
- `DOC002`: Empty or stub README file (High)
- `DOC003`: Missing Installation instructions (Medium)
- `DOC004`: Missing Usage examples (Low)
- `DOC005`: Missing LICENSE file or declaration (High)
- `DOC006`: Missing CONTRIBUTING guidelines (Low)

---

## 2. Dependency Analyzer (`dependencies`)
Inspects package manifests (`requirements.txt`, `pyproject.toml`, `package.json`).
- `DEP001`: Unpinned dependencies (Low)
- `DEP002`: Known security vulnerability via OSV API (High)
- `DEP003`: Outdated dependency release via PyPI / npm registry (Low)

---

## 3. Security Analyzer (`security`)
Detects credentials, dangerous calls, and sensitive files.
- `SEC001`: Exposed AWS Access Key (Critical)
- `SEC002`: Exposed GitHub Personal Access Token (Critical)
- `SEC003`: Exposed Slack Webhook or Bot Token (High)
- `SEC004`: Exposed Cryptographic Private Key (Critical)
- `SEC005`: Generic Hardcoded Secret / API Key (High)
- `SEC006`: `subprocess(..., shell=True)` (High)
- `SEC007`: `eval()` or `exec()` usage (High)
- `SEC008`: Unignored `.env` file committed to git (High)

---

## 4. Testing Analyzer (`testing`)
Detects test suites, frameworks, and CI execution.
- `TEST001`: Missing test files or directories (High)
- `TEST002`: Low test-to-source file volume ratio (Medium)
- `TEST003`: Test framework configured without test files (High)
- `TEST004`: CI workflows lack automated test steps (Medium)

---

## 5. Code Quality Analyzer (`code_quality`)
Performs modular Python AST analysis.
- `QUAL001`: File exceeds line count limit (> 500 lines) (Low)
- `QUAL002`: Wildcard import `from module import *` (Low)
- `QUAL003`: Function exceeds line length limit (> 50 lines) (Low)
- `QUAL004`: Function has excessive parameters (> 6 args) (Low)
- `QUAL005`: Function has high McCabe cyclomatic complexity (> 10) (Medium)

---

## 6. CI/CD Analyzer (`cicd`)
Inspects `.github/workflows` automation and permissions.
- `CICD001`: Missing GitHub Actions workflows (Medium)
- `CICD002`: Excessive `permissions: write-all` (High)
- `CICD003`: Missing explicit least-privilege permissions (Low)
- `CICD004`: Action pinned to mutable branch reference `@main` (Medium)
- `CICD005`: Malformed workflow YAML (High)
