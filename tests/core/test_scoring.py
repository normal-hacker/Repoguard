"""Tests for the transparent health scoring engine."""

from __future__ import annotations

from repoguard.config import RepoGuardConfig
from repoguard.core.findings import Category, Finding, Severity
from repoguard.core.scanner import AnalyzerExecutionResult
from repoguard.core.scoring import HealthScore


def test_perfect_health_score() -> None:
    config = RepoGuardConfig()
    findings: list[Finding] = []
    analyzer_results = {
        cat.value: AnalyzerExecutionResult(
            name=cat.value, category=cat.value, status="success", findings_count=0
        )
        for cat in Category
    }

    score = HealthScore.calculate(findings, analyzer_results, config)
    assert score.overall_score == 100.0
    assert score.grade == "A"
    for cat_data in score.breakdown.values():
        assert cat_data.score == 100.0
        assert cat_data.status == "evaluated"
        assert cat_data.deductions == 0.0


def test_severity_penalties_and_deductions() -> None:
    config = RepoGuardConfig()
    findings = [
        # Documentation: 1 High (-15) -> 85.0
        Finding(
            id="DOC001",
            analyzer="documentation",
            category=Category.DOCUMENTATION,
            severity=Severity.HIGH,
            description="Missing README",
            remediation="Add README",
        ),
        # Security: 1 Critical (-25) -> 75.0
        Finding(
            id="SEC001",
            analyzer="security",
            category=Category.SECURITY,
            severity=Severity.CRITICAL,
            description="AWS key",
            remediation="Revoke key",
        ),
        # Code Quality: 1 Medium (-8), 1 Low (-3) -> 89.0
        Finding(
            id="QUAL005",
            analyzer="code_quality",
            category=Category.CODE_QUALITY,
            severity=Severity.MEDIUM,
            description="High complexity",
            remediation="Refactor",
        ),
        Finding(
            id="QUAL004",
            analyzer="code_quality",
            category=Category.CODE_QUALITY,
            severity=Severity.LOW,
            description="Too many arguments",
            remediation="Group args",
        ),
    ]

    analyzer_results = {
        cat.value: AnalyzerExecutionResult(name=cat.value, category=cat.value, status="success")
        for cat in Category
    }

    score = HealthScore.calculate(findings, analyzer_results, config)

    doc_breakdown = score.breakdown[Category.DOCUMENTATION]
    assert doc_breakdown.score == 85.0
    assert doc_breakdown.deductions == 15.0

    sec_breakdown = score.breakdown[Category.SECURITY]
    assert sec_breakdown.score == 75.0
    assert sec_breakdown.deductions == 25.0

    qual_breakdown = score.breakdown[Category.CODE_QUALITY]
    assert qual_breakdown.score == 89.0
    assert qual_breakdown.deductions == 11.0

    # Dependencies (100), Testing (100), CI/CD (100)
    # Expected overall:
    # (85*0.15) + (89*0.25) + (75*0.25) + (100*0.15) + (100*0.10) + (100*0.10) =
    # 12.75 + 22.25 + 18.75 + 15.0 + 10.0 + 10.0 = 88.75 -> 88.8 (rounded)
    assert score.overall_score == 88.8
    assert score.grade == "B"


def test_score_never_drops_below_zero() -> None:
    config = RepoGuardConfig()
    # 10 critical findings in documentation = 250 deductions
    findings = [
        Finding(
            id=f"DOC{i:03d}",
            analyzer="documentation",
            category=Category.DOCUMENTATION,
            severity=Severity.CRITICAL,
            description=f"Critical issue {i}",
            file_path=f"file_{i}.md",
            remediation="Fix it",
        )
        for i in range(10)
    ]
    analyzer_results = {
        "documentation": AnalyzerExecutionResult(
            name="documentation", category="documentation", status="success"
        )
    }

    score = HealthScore.calculate(findings, analyzer_results, config)
    assert score.breakdown[Category.DOCUMENTATION].score == 0.0


def test_no_double_counting_findings() -> None:
    config = RepoGuardConfig()
    # Identical findings repeated
    duplicate_finding = Finding(
        id="SEC001",
        analyzer="security",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        description="Duplicate finding",
        file_path="config.py",
        line_number=10,
        remediation="Fix",
    )
    findings = [duplicate_finding, duplicate_finding, duplicate_finding]
    analyzer_results = {
        "security": AnalyzerExecutionResult(name="security", category="security", status="success")
    }

    score = HealthScore.calculate(findings, analyzer_results, config)
    # Only deducted once: 100 - 25 = 75.0
    assert score.breakdown[Category.SECURITY].score == 75.0
    assert score.breakdown[Category.SECURITY].findings_count == 1


def test_unavailable_category_not_counted_as_successful() -> None:
    config = RepoGuardConfig()
    findings: list[Finding] = []
    analyzer_results = {
        # Dependencies skipped (e.g. offline mode)
        "dependencies": AnalyzerExecutionResult(
            name="dependencies", category="dependencies", status="skipped"
        )
    }

    score = HealthScore.calculate(findings, analyzer_results, config)
    dep_breakdown = score.breakdown[Category.DEPENDENCIES]
    assert dep_breakdown.status == "unavailable"
    assert dep_breakdown.score == 0.0
    # Unavailable category is excluded from positive weighting
    assert "skipped or unavailable" in dep_breakdown.explanation


def test_disclaimer_and_methodology_present() -> None:
    config = RepoGuardConfig()
    score = HealthScore.calculate([], {}, config)
    assert "NOT a guarantee or warranty of security" in score.disclaimer
    assert "methodology" in score.model_fields
    assert len(score.methodology) > 20
