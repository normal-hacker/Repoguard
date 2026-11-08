"""Tests for RepoScanner execution, fault-tolerance, and threshold evaluation."""

from __future__ import annotations

from pathlib import Path

from repoguard.config import RepoGuardConfig
from repoguard.core.findings import Category, Finding, Severity
from repoguard.core.registry import AnalyzerRegistry
from repoguard.core.scanner import RepoScanner
from repoguard.plugins.base import BaseAnalyzer


class SampleDocAnalyzer(BaseAnalyzer):
    name = "mock_doc"
    description = "Mock documentation analyzer"
    category = Category.DOCUMENTATION

    def analyze(self, context) -> list[Finding]:
        if not context.has_file("README.md"):
            return [
                Finding(
                    id="DOC001",
                    analyzer=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    description="Missing README.md",
                    remediation="Create a README.md",
                )
            ]
        return []


class CrashingAnalyzer(BaseAnalyzer):
    name = "crashing_analyzer"
    description = "Simulates an unhandled bug in an analyzer"
    category = Category.CODE_QUALITY

    def analyze(self, context) -> list[Finding]:
        raise RuntimeError("Unexpected internal crash!")


class NetworkRequiringAnalyzer(BaseAnalyzer):
    name = "network_analyzer"
    description = "Requires network connection"
    category = Category.DEPENDENCIES

    def is_available(self, context) -> bool:
        return context.network_enabled

    def analyze(self, context) -> list[Finding]:
        return []


def test_scanner_executes_registered_analyzers(temp_repo: Path) -> None:
    # No README exists -> should yield 1 finding
    reg = AnalyzerRegistry()
    reg.register(SampleDocAnalyzer)

    scanner = RepoScanner(repo_root=temp_repo, analyzer_registry=reg)
    result = scanner.run()

    assert result.total_findings == 1
    assert result.findings[0].id == "DOC001"
    assert result.analyzer_results["mock_doc"].status == "success"
    assert result.analyzer_results["mock_doc"].findings_count == 1


def test_scanner_handles_analyzer_crashes_gracefully(temp_repo: Path) -> None:
    reg = AnalyzerRegistry()
    reg.register(SampleDocAnalyzer)
    reg.register(CrashingAnalyzer)

    scanner = RepoScanner(repo_root=temp_repo, analyzer_registry=reg)
    result = scanner.run()

    # Scan still succeeds overall despite one analyzer crashing
    assert "crashing_analyzer" in result.analyzer_results
    assert result.analyzer_results["crashing_analyzer"].status == "failed"
    assert "Unexpected internal crash!" in str(
        result.analyzer_results["crashing_analyzer"].error_message
    )

    # The other analyzer still produced its finding
    assert result.analyzer_results["mock_doc"].status == "success"
    assert result.total_findings == 1


def test_scanner_skips_when_prerequisites_unmet(temp_repo: Path) -> None:
    reg = AnalyzerRegistry()
    reg.register(NetworkRequiringAnalyzer)

    cfg = RepoGuardConfig()
    cfg.network.enabled = False

    scanner = RepoScanner(repo_root=temp_repo, config=cfg, analyzer_registry=reg)
    result = scanner.run()

    assert result.analyzer_results["network_analyzer"].status == "skipped"


def test_scanner_exit_code_thresholds(temp_repo: Path) -> None:
    reg = AnalyzerRegistry()
    reg.register(SampleDocAnalyzer)

    # High finding detected, threshold is high -> exit code 1
    cfg_fail = RepoGuardConfig()
    cfg_fail.thresholds.fail_on_severity = "high"
    scanner_fail = RepoScanner(repo_root=temp_repo, config=cfg_fail, analyzer_registry=reg)
    assert scanner_fail.run().exit_code == 1

    # High finding detected, but threshold is critical -> exit code 0
    cfg_pass = RepoGuardConfig()
    cfg_pass.thresholds.fail_on_severity = "critical"
    scanner_pass = RepoScanner(repo_root=temp_repo, config=cfg_pass, analyzer_registry=reg)
    assert scanner_pass.run().exit_code == 0
