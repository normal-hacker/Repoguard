"""Tests for DocumentationAnalyzer."""

from __future__ import annotations

from pathlib import Path

from repoguard.analyzers.documentation import DocumentationAnalyzer
from repoguard.core.context import ScanContext


def test_missing_readme_and_license(temp_repo: Path) -> None:
    ctx = ScanContext(repo_root=temp_repo)
    analyzer = DocumentationAnalyzer()
    findings = analyzer.analyze(ctx)

    finding_ids = [f.id for f in findings]
    assert "DOC001" in finding_ids  # Missing README
    assert "DOC005" in finding_ids  # Missing LICENSE
    assert "DOC006" in finding_ids  # Missing CONTRIBUTING


def test_empty_readme(temp_repo: Path) -> None:
    (temp_repo / "README.md").write_text("Too short", encoding="utf-8")
    (temp_repo / "LICENSE").write_text("MIT License", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = DocumentationAnalyzer()
    findings = analyzer.analyze(ctx)

    finding_ids = [f.id for f in findings]
    assert "DOC002" in finding_ids  # README too short


def test_comprehensive_readme_and_docs(temp_repo: Path) -> None:
    readme_content = """# Awesome Project

A complete, production-grade tool for repository analysis.

## Installation

```bash
pip install awesome-project
```

## Usage

```bash
awesome run .
```

## Contributing

See our contribution guidelines below.

## License

MIT License.
"""
    (temp_repo / "README.md").write_text(readme_content, encoding="utf-8")
    (temp_repo / "LICENSE").write_text("MIT License Copyright 2026", encoding="utf-8")
    (temp_repo / "CONTRIBUTING.md").write_text("# Contributing\nPlease open PRs.", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = DocumentationAnalyzer()
    findings = analyzer.analyze(ctx)

    # Should have zero documentation issues
    assert len(findings) == 0


def test_missing_sections_in_readme(temp_repo: Path) -> None:
    readme_content = """# Awesome Project

A great project that does things. It is very long and has lots of words describing how awesome
it is and why everyone in the developer community should be using it immediately for their workflows.
"""
    (temp_repo / "README.md").write_text(readme_content, encoding="utf-8")
    (temp_repo / "LICENSE").write_text("MIT", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = DocumentationAnalyzer()
    findings = analyzer.analyze(ctx)

    finding_ids = [f.id for f in findings]
    assert "DOC003" in finding_ids  # Missing Installation
    assert "DOC004" in finding_ids  # Missing Usage
