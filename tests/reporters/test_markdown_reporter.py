"""Tests for MarkdownReporter generation."""

from __future__ import annotations

from repoguard.config import RepoGuardConfig
from repoguard.core.findings import Category, Finding, Severity
from repoguard.core.scanner import AnalyzerExecutionResult, ScanResult
from repoguard.core.scoring import HealthScore
from repoguard.reporters.markdown import MarkdownReporter


def test_markdown_reporter_rendering() -> None:
    config = RepoGuardConfig()
    finding = Finding(
        id="DOC001",
        analyzer="documentation",
        category=Category.DOCUMENTATION,
        severity=Severity.HIGH,
        description="Missing README",
        remediation="Create README.md",
    )
    analyzer_results = {
        "documentation": AnalyzerExecutionResult(
            name="documentation",
            category="documentation",
            status="success",
            findings_count=1,
            duration_seconds=0.1,
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

    md = MarkdownReporter.render(result)
    assert "# 🛡️ RepoGuard Repository Health Report" in md
    assert "Health Score:" in md
    assert "Category Breakdown" in md
    assert "Findings & Remediation" in md
    assert "[DOC001] Missing README" in md
    assert "Create README.md" in md
    assert "Analyzers Executed" in md
