# Security Policy

The RepoGuard project takes the security of our developer tooling seriously.

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

---

## Reporting a Vulnerability

If you discover a security vulnerability within RepoGuard, please do **NOT** open a public issue.

Instead, please send a responsible disclosure email to:
**security@repoguard.dev**

Include:
- A description of the vulnerability and potential attack vectors.
- Steps to reproduce or a minimal proof of concept.
- Affected versions.

We will acknowledge receipt within 48 hours and work with you on a coordinated disclosure timeline.

---

## Core Security Safeguards in RepoGuard

RepoGuard enforces strict security invariants:
1. **Never executes repository code**: Analyzers use static analysis, AST parsing, and pattern matching.
2. **Never transmits source code**: Repository source code is never sent to external AI or third-party cloud services.
3. **Secret Masking**: All credential scanning masks evidence strings.
4. **Filesystem Safety**: Path traversal attempts are blocked via `safe_resolve_path`.
5. **Offline Mode**: Supported via `--no-network` to disable all outbound HTTP calls.
