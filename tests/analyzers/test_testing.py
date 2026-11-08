"""Tests for TestingAnalyzer: test detection, framework discovery, and CI verification."""

from __future__ import annotations

from pathlib import Path

from repoguard.analyzers.testing import TestingAnalyzer
from repoguard.core.context import ScanContext


def test_missing_test_files(temp_repo: Path) -> None:
    (temp_repo / "main.py").write_text("print('hello')", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = TestingAnalyzer()
    findings = analyzer.analyze(ctx)

    finding_ids = [f.id for f in findings]
    assert "TEST001" in finding_ids


def test_framework_configured_without_tests(temp_repo: Path) -> None:
    (temp_repo / "pytest.ini").write_text("[pytest]\ntestpaths = tests\n", encoding="utf-8")
    (temp_repo / "main.py").write_text("print('hello')", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = TestingAnalyzer()
    findings = analyzer.analyze(ctx)

    finding_ids = [f.id for f in findings]
    assert "TEST003" in finding_ids


def test_ci_missing_tests_step(temp_repo: Path) -> None:
    tests_dir = temp_repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_main.py").write_text("def test_dummy(): pass", encoding="utf-8")

    wf_dir = temp_repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    # Workflow that does linting only, no tests
    (wf_dir / "ci.yml").write_text(
        """name: CI
on: [push]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ruff check .
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = TestingAnalyzer()
    findings = analyzer.analyze(ctx)

    finding_ids = [f.id for f in findings]
    assert "TEST004" in finding_ids


def test_healthy_testing_setup(temp_repo: Path) -> None:
    tests_dir = temp_repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_main.py").write_text("def test_ok(): assert True", encoding="utf-8")

    wf_dir = temp_repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        """name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pytest -v
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = TestingAnalyzer()
    findings = analyzer.analyze(ctx)

    assert len(findings) == 0
