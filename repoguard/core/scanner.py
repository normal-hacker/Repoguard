"""Core repository scanner executing registered analyzers safely and aggregating findings."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from repoguard.config import RepoGuardConfig
from repoguard.core.context import ScanContext
from repoguard.core.findings import Category, Finding, Severity
from repoguard.core.registry import AnalyzerRegistry
from repoguard.core.registry import registry as default_registry
from repoguard.core.scoring import HealthScore


class AnalyzerExecutionResult(BaseModel):
    """Execution status and performance metrics for an analyzer."""

    name: str
    category: str
    status: str = Field(..., description="One of: success, failed, skipped")
    duration_seconds: float = 0.0
    findings_count: int = 0
    error_message: str | None = None


class ScanResult(BaseModel):
    """Consolidated result of a repository scan."""

    repo_root: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_seconds: float = 0.0
    findings: list[Finding] = Field(default_factory=list)
    analyzer_results: dict[str, AnalyzerExecutionResult] = Field(default_factory=dict)
    score: HealthScore | None = None
    config: RepoGuardConfig = Field(default_factory=RepoGuardConfig)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def findings_by_category(self) -> dict[Category, list[Finding]]:
        """Group findings by category."""
        grouped: dict[Category, list[Finding]] = {cat: [] for cat in Category}
        for finding in self.findings:
            grouped[finding.category].append(finding)
        return grouped

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        """Group findings by severity level."""
        grouped: dict[Severity, list[Finding]] = {sev: [] for sev in Severity}
        for finding in self.findings:
            grouped[finding.severity].append(finding)
        return grouped

    def has_severity(self, threshold: Severity | str) -> bool:
        """Check if any finding meets or exceeds the given severity threshold."""
        return any(f.severity.meets_threshold(threshold) for f in self.findings)

    @property
    def exit_code(self) -> int:
        """Calculate exit code based on configured thresholds.

        Returns:
            0: Scan passed all threshold checks
            1: Threshold exceeded (e.g. high/critical findings or score below minimum)
        """
        # Check minimum score threshold
        min_score = self.config.thresholds.min_score
        if self.score and self.score.overall_score < min_score:
            return 1

        # Check fail-on severity threshold
        fail_sev = self.config.thresholds.fail_on_severity
        if fail_sev and self.has_severity(fail_sev):
            return 1

        return 0


class RepoScanner:
    """Orchestrates repository scanning across all registered analyzers."""

    def __init__(
        self,
        repo_root: Path,
        config: RepoGuardConfig | None = None,
        analyzer_registry: AnalyzerRegistry | None = None,
    ) -> None:
        # Ensure built-in analyzers are loaded into default registry
        import repoguard.analyzers  # noqa: F401

        self.repo_root = repo_root.resolve()
        self.config = config or RepoGuardConfig.load(repo_root=self.repo_root)
        self.registry = analyzer_registry or default_registry
        self.context = ScanContext(repo_root=self.repo_root, config=self.config)

    def run(
        self,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> ScanResult:
        """Run all registered analyzers against the target repository."""
        start_time = time.perf_counter()
        analyzer_classes = self.registry.list_all()

        unique_findings: dict[str, Finding] = {}
        execution_results: dict[str, AnalyzerExecutionResult] = {}

        for analyzer_cls in analyzer_classes:
            analyzer_name = analyzer_cls.name
            analyzer_category = (
                analyzer_cls.category.value
                if isinstance(analyzer_cls.category, Category)
                else str(analyzer_cls.category)
            )

            if progress_callback:
                progress_callback(analyzer_name, "running")

            analyzer_config: dict[str, Any] = self.config.analyzers.get(analyzer_name, {})
            analyzer_instance = analyzer_cls(config=analyzer_config)

            # Check availability (e.g. network requirement)
            if not analyzer_instance.is_available(self.context):
                if progress_callback:
                    progress_callback(analyzer_name, "skipped")
                execution_results[analyzer_name] = AnalyzerExecutionResult(
                    name=analyzer_name,
                    category=analyzer_category,
                    status="skipped",
                    duration_seconds=0.0,
                    findings_count=0,
                    error_message="Analyzer skipped: prerequisites not met (e.g. offline mode)",
                )
                continue

            analyzer_start = time.perf_counter()
            try:
                findings = analyzer_instance.analyze(self.context)
                duration = time.perf_counter() - analyzer_start

                new_count = 0
                for f in findings:
                    if f.fingerprint not in unique_findings:
                        unique_findings[f.fingerprint] = f
                        new_count += 1

                execution_results[analyzer_name] = AnalyzerExecutionResult(
                    name=analyzer_name,
                    category=analyzer_category,
                    status="success",
                    duration_seconds=duration,
                    findings_count=len(findings),
                )
                if progress_callback:
                    progress_callback(analyzer_name, "completed")

            except Exception as exc:  # Catch any unexpected failure in analyzer
                duration = time.perf_counter() - analyzer_start
                execution_results[analyzer_name] = AnalyzerExecutionResult(
                    name=analyzer_name,
                    category=analyzer_category,
                    status="failed",
                    duration_seconds=duration,
                    findings_count=0,
                    error_message=f"Analyzer crashed: {exc}",
                )
                if progress_callback:
                    progress_callback(analyzer_name, "failed")

        total_duration = time.perf_counter() - start_time
        sorted_findings = sorted(
            unique_findings.values(),
            key=lambda item: (item.severity.level, item.category.value),
            reverse=True,
        )

        health_score = HealthScore.calculate(
            findings=sorted_findings,
            analyzer_results=execution_results,
            config=self.config,
        )

        return ScanResult(
            repo_root=str(self.repo_root),
            duration_seconds=total_duration,
            findings=sorted_findings,
            analyzer_results=execution_results,
            score=health_score,
            config=self.config,
        )
