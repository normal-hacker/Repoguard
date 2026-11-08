"""Tests for TerminalReporter rich output."""

from __future__ import annotations

from rich.console import Console

from repoguard.config import RepoGuardConfig
from repoguard.core.findings import Category, Finding, Severity
from repoguard.core.scanner import AnalyzerExecutionResult, ScanResult
from repoguard.core.scoring import HealthScore
from repoguard.reporters.terminal import TerminalReporter


def test_terminal_reporter_rendering() -> None:
    test_console = Console(record=True, width=120)
    reporter = TerminalReporter(console=test_console)

    config = RepoGuardConfig()
    finding = Finding(
        id="QUAL001",
        analyzer="code_quality",
        category=Category.CODE_QUALITY,
        severity=Severity.LOW,
        description="File too large",
        file_path="big.py",
        remediation="Split into modules",
    )
    analyzer_results = {
        "code_quality": AnalyzerExecutionResult(
            name="code_quality",
            category="code_quality",
            status="success",
            findings_count=1,
            duration_seconds=0.02,
        )
    }
    score = HealthScore.calculate([finding], analyzer_results, config)

    result = ScanResult(
        repo_root="/repo",
        findings=[finding],
        analyzer_results=analyzer_results,
        score=score,
        config=config,
    )

    reporter.render(result)
    output = test_console.export_text()

    assert "RepoGuard Health Assessment" in output
    assert "Category Breakdown" in output
    assert "Detected Findings" in output
    assert "QUAL001" in output
    assert "File too large" in output
