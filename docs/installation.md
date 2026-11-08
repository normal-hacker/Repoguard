# Installation Guide

RepoGuard is packaged as a standard Python tool and requires **Python 3.11+**.

---

## 1. Using pip

```bash
pip install repoguard
```

## 2. Using pipx (Recommended for CLI Tools)

```bash
pipx install repoguard
```

## 3. Verifying Installation

Verify that the CLI is accessible from your shell:

```bash
repoguard version
```

Output:
```text
                         RepoGuard System Information                          
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Component            ┃ Details                                              ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ RepoGuard Version    │ 0.1.0                                                │
│ Python Version       │ 3.11+                                                │
│ License              │ MIT                                                  │
│ Tagline              │ Analyze. Detect. Improve.                            │
└──────────────────────┴──────────────────────────────────────────────────────┘
```

---

## 4. Development Installation

To install from source for local development:

```bash
git clone https://github.com/repoguard/repoguard.git
cd repoguard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run test suite:
```bash
pytest -v
```
