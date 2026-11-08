# Architecture Documentation

RepoGuard is designed around a decoupled, modular pipeline built for CLI and CI execution.

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI / Action                        │
│                 (Typer, Rich, GitHub Action)                │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                         ScanContext                         │
│   • Safe Path Resolution (Traversal Guard)                  │
│   • Exclusion Filtering (.gitignore + custom)               │
│   • File Caching & Safe Reading (< 2 MB Cap)                │
│   • Git Repository Introspection (GitPython)                │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                      Analyzer Registry                      │
│   • Duplicate Prevention & Metadata Validation              │
│   • Built-in Analyzers:                                     │
│     - Documentation, Dependencies, Security                 │
│     - Code Quality, Testing, CI/CD                          │
│   • Third-Party Plugin Discovery ('repoguard.plugins')      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                     RepoScanner Engine                      │
│   • Isolated Execution (Catches Crashes Gracefully)         │
│   • Deduplication via Deterministic Fingerprinting          │
│   • Transparent Scoring Engine (0-100 & Grade)              │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                          Reporters                          │
│   • Rich Terminal  • JSON Schema  • GitHub-Flavored MD      │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Tenets

1. **Safety First**: Never execute untrusted repository code.
2. **Never Expose Secrets**: Mask detected credentials in logs and outputs.
3. **Resilience**: A bug or crash in an individual analyzer never terminates the scan.
4. **Transparent Scoring**: Explain exact deductions; avoid double-counting.
5. **Extensibility**: Third-party plugins install via entry points without altering core.
