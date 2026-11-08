"""Transparent repository health scoring engine."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from repoguard.config import RepoGuardConfig
from repoguard.core.findings import Category, Finding, Severity

DISCLAIMER: str = (
    "The RepoGuard Health Score is an automated project-maintenance and hygiene indicator "
    "evaluating documentation, dependencies, testing, security, code quality, and CI/CD best practices. "
    "It is NOT a guarantee or warranty of security or vulnerability-free software."
)

METHODOLOGY: str = (
    "Each category starts at 100 points. Penalties are deducted based on unique finding severities: "
    "Critical (-25), High (-15), Medium (-8), Low (-3), Info (0). Category scores are clamped to [0, 100]. "
    "The overall score is computed as the normalized weighted sum of evaluated categories based on configured weights. "
    "Unavailable or skipped checks are excluded from positive weighting and explicitly reported."
)

# Standard penalty points by severity
SEVERITY_PENALTIES: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}


class CategoryBreakdown(BaseModel):
    """Detailed score breakdown and evaluation status for a category."""

    category: Category
    score: float = Field(..., ge=0.0, le=100.0)
    weight: float = Field(..., ge=0.0, le=1.0)
    status: str = Field(..., description="'evaluated', 'unavailable', or 'failed'")
    findings_count: int = 0
    deductions: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    explanation: str


class HealthScore(BaseModel):
    """Overall repository health score, category breakdown, and scoring methodology."""

    overall_score: float = Field(..., ge=0.0, le=100.0)
    grade: str
    breakdown: dict[Category, CategoryBreakdown]
    weights_used: dict[str, float]
    disclaimer: str = DISCLAIMER
    methodology: str = METHODOLOGY

    @classmethod
    def calculate(
        cls,
        findings: list[Finding],
        analyzer_results: dict[str, Any],
        config: RepoGuardConfig,
    ) -> HealthScore:
        """Calculate transparent category breakdown and overall health score."""
        weights = config.scoring_weights

        weight_map: dict[Category, float] = {
            Category.DOCUMENTATION: weights.documentation,
            Category.CODE_QUALITY: weights.code_quality,
            Category.SECURITY: weights.security,
            Category.DEPENDENCIES: weights.dependencies,
            Category.TESTING: weights.testing,
            Category.CICD: weights.cicd,
        }

        # Deduplicate findings by fingerprint to guarantee no double counting
        unique_findings_by_category: dict[Category, dict[str, Finding]] = {
            cat: {} for cat in Category
        }
        for f in findings:
            if f.category in unique_findings_by_category:
                unique_findings_by_category[f.category][f.fingerprint] = f

        breakdown: dict[Category, CategoryBreakdown] = {}
        total_eval_weight = 0.0
        weighted_sum = 0.0

        for cat in [
            Category.DOCUMENTATION,
            Category.CODE_QUALITY,
            Category.SECURITY,
            Category.DEPENDENCIES,
            Category.TESTING,
            Category.CICD,
        ]:
            cat_findings = list(unique_findings_by_category[cat].values())
            cat_weight = weight_map.get(cat, 0.0)

            # Determine category evaluation status from analyzer results
            analyzer_key = cat.value
            a_res = analyzer_results.get(analyzer_key)

            if a_res and a_res.status == "skipped":
                status = "unavailable"
                score = 0.0
                deductions = 0.0
                explanation = "Category checks were skipped or unavailable (e.g., offline mode)."
            elif a_res and a_res.status == "failed":
                status = "failed"
                score = 0.0
                deductions = 100.0
                explanation = f"Analyzer crashed during evaluation: {a_res.error_message}"
                total_eval_weight += cat_weight
                weighted_sum += 0.0
            else:
                status = "evaluated"
                # Compute deductions from unique findings
                crit = sum(1 for f in cat_findings if f.severity == Severity.CRITICAL)
                high = sum(1 for f in cat_findings if f.severity == Severity.HIGH)
                med = sum(1 for f in cat_findings if f.severity == Severity.MEDIUM)
                low = sum(1 for f in cat_findings if f.severity == Severity.LOW)

                deductions = sum(SEVERITY_PENALTIES[f.severity] for f in cat_findings)
                score = max(0.0, 100.0 - deductions)

                explanation = (
                    f"{len(cat_findings)} unique findings: {crit} critical, {high} high, {med} medium, {low} low. "
                    f"Deducted {deductions:.0f} pts from 100."
                )

                total_eval_weight += cat_weight
                weighted_sum += score * cat_weight

            breakdown[cat] = CategoryBreakdown(
                category=cat,
                score=round(score, 1),
                weight=cat_weight,
                status=status,
                findings_count=len(cat_findings),
                deductions=round(deductions, 1),
                critical_count=sum(1 for f in cat_findings if f.severity == Severity.CRITICAL),
                high_count=sum(1 for f in cat_findings if f.severity == Severity.HIGH),
                medium_count=sum(1 for f in cat_findings if f.severity == Severity.MEDIUM),
                low_count=sum(1 for f in cat_findings if f.severity == Severity.LOW),
                explanation=explanation,
            )

        overall = round(weighted_sum / total_eval_weight, 1) if total_eval_weight > 0 else 0.0

        grade = cls._grade_for_score(overall)

        return HealthScore(
            overall_score=overall,
            grade=grade,
            breakdown=breakdown,
            weights_used=weights.model_dump(),
        )

    @staticmethod
    def _grade_for_score(score: float) -> str:
        if score >= 90.0:
            return "A"
        if score >= 80.0:
            return "B"
        if score >= 70.0:
            return "C"
        if score >= 60.0:
            return "D"
        return "F"
