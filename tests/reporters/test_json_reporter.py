"""Tests for JsonReporter and JSON schema validity."""

from __future__ import annotations

import json

from repoguard.config import RepoGuardConfig
from repoguard.core.findings import Category, Finding, Severity
from repoguard.core.scanner import AnalyzerExecutionResult, ScanResult
from repoguard.core.scoring import HealthScore
from repoguard.reporters.json_reporter import JsonReporter


def test_json_reporter_render_and_schema() -> None:
    config = RepoGuardConfig()
    finding = Finding(
        id="SEC001",
        analyzer="security",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        description="Hardcoded credential",
        file_path="auth.py",
        line_number=12,
        remediation="Use vault",
    )
    analyzer_results = {
        "security": AnalyzerExecutionResult(
            name="security",
            category="security",
            status="success",
            findings_count=1,
            duration_seconds=0.05,
        )
    }
    score = HealthScore.calculate([finding], analyzer_results, config)

    result = ScanResult(
        repo_root="/test/repo",
        findings=[finding],
        analyzer_results=analyzer_results,
        score=score,
        config=config,
    )

    rendered_json = JsonReporter.render(result)
    parsed = json.loads(rendered_json)

    assert parsed["repo_root"] == "/test/repo"
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["id"] == "SEC001"
    assert parsed["findings"][0]["category"] == "security"
    assert parsed["findings"][0]["severity"] == "high"
    assert "score" in parsed
    assert parsed["score"]["overall_score"] is not None

    # Check JSON Schema
    schema = JsonReporter.get_schema()
    assert schema["type"] == "object"
    assert "properties" in schema
    assert "findings" in schema["properties"]
    assert "score" in schema["properties"]
