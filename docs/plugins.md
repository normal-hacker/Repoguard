# Plugin Development Guide

RepoGuard features a first-class plugin system allowing third-party developers to register custom analyzers.

---

## 1. Implement BaseAnalyzer

Create a Python class inheriting from `repoguard.plugins.base.BaseAnalyzer`:

```python
from repoguard.plugins.base import BaseAnalyzer
from repoguard.core.context import ScanContext
from repoguard.core.findings import Category, Finding, Severity


class MyCustomAnalyzer(BaseAnalyzer):
    name = "custom_check"
    description = "Checks custom architectural rules"
    category = Category.CUSTOM
    version = "1.0.0"

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings = []
        for file in context.files:
            # Safe reading helper
            content = context.read_file(file)
            if content and "FORBIDDEN" in content:
                findings.append(
                    Finding(
                        id="CUST001",
                        analyzer=self.name,
                        category=self.category,
                        severity=Severity.MEDIUM,
                        description="Forbidden token found",
                        file_path=context.get_relative_path(file),
                        remediation="Remove the forbidden token",
                    )
                )
        return findings
```

---

## 2. Register Entry Point in pyproject.toml

```toml
[project.entry-points."repoguard.plugins"]
custom_check = "my_package.analyzer:MyCustomAnalyzer"
```

---

## 3. Install and Inspect

```bash
pip install -e .
repoguard plugins list
repoguard plugins info custom_check
```

RepoGuard automatically isolates plugin crashes during execution without failing overall scans.
