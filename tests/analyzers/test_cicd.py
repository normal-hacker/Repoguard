"""Tests for CiCdAnalyzer: workflow presence, permissions, and mutable action pinning."""

from __future__ import annotations

from pathlib import Path

from repoguard.analyzers.cicd import CiCdAnalyzer
from repoguard.core.context import ScanContext


def test_missing_workflows(temp_repo: Path) -> None:
    ctx = ScanContext(repo_root=temp_repo)
    analyzer = CiCdAnalyzer()
    findings = analyzer.analyze(ctx)

    missing_findings = [f for f in findings if f.id == "CICD001"]
    assert len(missing_findings) == 1


def test_excessive_write_all_permissions(temp_repo: Path) -> None:
    wf_dir = temp_repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "build.yml").write_text(
        """name: Build
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4.1.0
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = CiCdAnalyzer()
    findings = analyzer.analyze(ctx)

    perm_findings = [f for f in findings if f.id == "CICD002"]
    assert len(perm_findings) == 1
    assert "write-all" in perm_findings[0].description


def test_unpinned_mutable_branch_action(temp_repo: Path) -> None:
    wf_dir = temp_repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "build.yml").write_text(
        """name: Build
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = CiCdAnalyzer()
    findings = analyzer.analyze(ctx)

    pin_findings = [f for f in findings if f.id == "CICD004"]
    assert len(pin_findings) == 1
    assert "@main" in pin_findings[0].description


def test_malformed_workflow_yaml(temp_repo: Path) -> None:
    wf_dir = temp_repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "broken.yml").write_text(
        """name: Broken
on: [push
jobs:
  bad:
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = CiCdAnalyzer()
    findings = analyzer.analyze(ctx)

    malformed = [f for f in findings if f.id == "CICD005"]
    assert len(malformed) == 1
