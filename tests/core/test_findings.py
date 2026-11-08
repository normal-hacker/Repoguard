"""Tests for Finding model, severity hierarchy, and deduplication."""

from __future__ import annotations

from pathlib import Path

import pytest

from repoguard.core.findings import Category, Confidence, Finding, Severity


def test_severity_ordering() -> None:
    assert Severity.INFO.level < Severity.LOW.level
    assert Severity.LOW.level < Severity.MEDIUM.level
    assert Severity.MEDIUM.level < Severity.HIGH.level
    assert Severity.HIGH.level < Severity.CRITICAL.level

    assert Severity.CRITICAL.meets_threshold(Severity.HIGH) is True
    assert Severity.HIGH.meets_threshold(Severity.HIGH) is True
    assert Severity.MEDIUM.meets_threshold(Severity.HIGH) is False
    assert Severity.LOW.meets_threshold("medium") is False
    assert Severity.HIGH.meets_threshold("medium") is True


def test_finding_creation_and_normalization() -> None:
    finding = Finding(
        id="DOC001",
        analyzer="documentation",
        category=Category.DOCUMENTATION,
        severity=Severity.HIGH,
        description="Missing README.md file",
        file_path=Path("docs/README.md"),
        line_number=10,
        evidence="File not found",
        remediation="Create a comprehensive README.md",
        confidence=Confidence.HIGH,
    )

    assert finding.id == "DOC001"
    assert finding.file_path == "docs/README.md"
    assert finding.line_number == 10
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH
    assert len(finding.fingerprint) == 16


def test_finding_deduplication() -> None:
    f1 = Finding(
        id="SEC001",
        analyzer="security",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        description="Hardcoded API secret found",
        file_path="config.py",
        line_number=42,
        remediation="Move secret to environment variable",
    )

    f2 = Finding(
        id="SEC001",
        analyzer="security",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        description="Hardcoded API secret found",
        file_path="config.py",
        line_number=42,
        remediation="Move secret to environment variable",
    )

    f3 = Finding(
        id="SEC001",
        analyzer="security",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        description="Hardcoded API secret found",
        file_path="config.py",
        line_number=99,  # Different line
        remediation="Move secret to environment variable",
    )

    # Identical findings have identical fingerprints and are equal
    assert f1 == f2
    assert f1 != f3
    assert len({f1, f2, f3}) == 2


def test_finding_immutability() -> None:
    finding = Finding(
        id="TEST001",
        analyzer="testing",
        category=Category.TESTING,
        severity=Severity.LOW,
        description="Low coverage",
        remediation="Add tests",
    )
    with pytest.raises((TypeError, ValueError)):
        finding.description = "New description"  # type: ignore[misc]
