"""Markdown report generator for CI/CD and pull request summaries."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from repoguard.core.scanner import ScanResult


class MarkdownReporter:
    """Generates a clean GitHub-Flavored Markdown report from scan results."""

    @staticmethod
    def render(result: ScanResult) -> str:
        lines: list[str] = [
            "# 🛡️ RepoGuard Repository Health Report",
            "",
            "> **Analyze. Detect. Improve.**",
            "",
        ]

        # Score & Grade Section
        if result.score:
            score = result.score
            badge_color = {
                "A": "brightgreen",
                "B": "green",
                "C": "yellow",
                "D": "orange",
                "F": "red",
            }.get(score.grade, "lightgrey")

            lines.extend(
                [
                    f"### Health Score: **{score.overall_score:.1f} / 100** (Grade: **{score.grade}**)",
                    f"![Health Score](https://img.shields.io/badge/Health_Score-{score.overall_score:.1f}%2F100-{badge_color})",
                    "",
                    f"- **Target Repository**: `{result.repo_root}`",
                    f"- **Scan Duration**: `{result.duration_seconds:.2f}s`",
                    f"- **Total Findings**: `{result.total_findings}`",
                    f"- **Timestamp**: `{result.timestamp.isoformat()}`",
                    "",
                    "### Category Breakdown",
                    "",
                    "| Category | Weight | Score | Findings | Status | Notes |",
                    "|:---|:---:|:---:|:---:|:---:|:---|",
                ]
            )

            for cat, data in score.breakdown.items():
                cat_name = cat.value.replace("_", " ").title()
                lines.append(
                    f"| **{cat_name}** | {data.weight * 100:.0f}% | {data.score:.1f} | {data.findings_count} | `{data.status}` | {data.explanation} |"
                )
            lines.append("")

        # Findings Section
        lines.extend(
            [
                "---",
                "### Findings & Remediation",
                "",
            ]
        )

        if not result.findings:
            lines.extend(
                [
                    "🎉 **No issues detected!** All evaluated checks passed cleanly.",
                    "",
                ]
            )
        else:
            for f in result.findings:
                sev_icon = {
                    "critical": "🚨 **CRITICAL**",
                    "high": "⚠️ **HIGH**",
                    "medium": "🟡 **MEDIUM**",
                    "low": "🔵 **LOW**",
                    "info": "ℹ️ **INFO**",
                }.get(f.severity.value, f.severity.value.upper())

                loc = f"`{f.file_path}`" if f.file_path else "*Repository-wide*"
                if f.line_number:
                    loc = f"{loc} (line {f.line_number})"

                lines.extend(
                    [
                        f"#### [{f.id}] {f.description}",
                        "",
                        f"- **Severity**: {sev_icon}",
                        f"- **Category**: `{f.category.value}`",
                        f"- **Analyzer**: `{f.analyzer}`",
                        f"- **Location**: {loc}",
                        f"- **Confidence**: `{f.confidence.value}`",
                    ]
                )

                if f.evidence:
                    lines.extend(
                        [
                            f"- **Evidence**: `{f.evidence}`",
                        ]
                    )

                lines.extend(
                    [
                        f"- **Remediation**: {f.remediation}",
                        "",
                    ]
                )

        # Analyzer Summary Section
        lines.extend(
            [
                "---",
                "### Analyzers Executed",
                "",
                "| Analyzer | Category | Status | Findings | Duration |",
                "|:---|:---|:---:|:---:|:---:|",
            ]
        )
        for a_res in result.analyzer_results.values():
            status_badge = (
                "✅ Success"
                if a_res.status == "success"
                else ("⏸️ Skipped" if a_res.status == "skipped" else "❌ Failed")
            )
            lines.append(
                f"| `{a_res.name}` | {a_res.category} | {status_badge} | {a_res.findings_count} | {a_res.duration_seconds:.3f}s |"
            )
        lines.append("")

        # Disclaimer
        if result.score:
            lines.extend(
                [
                    "> ℹ️ *" + result.score.disclaimer + "*",
                    "",
                ]
            )

        return "\n".join(lines)
