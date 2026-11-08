"""Rich terminal reporter providing human-readable interactive and CI output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if TYPE_CHECKING:
    from repoguard.core.scanner import ScanResult


class TerminalReporter:
    """Renders formatted tables, panels, and badges to the terminal using Rich."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, result: ScanResult) -> None:
        """Render the complete terminal report."""
        # 1. Health Score Banner
        if result.score:
            score = result.score
            grade_color = {
                "A": "bold green",
                "B": "bold cyan",
                "C": "bold yellow",
                "D": "bold red",
                "F": "bold white on red",
            }.get(score.grade, "bold white")

            score_text = (
                f"[bold]Health Score:[/] [{grade_color}]{score.overall_score:.1f} / 100[/]  "
                f"([bold]Grade:[/] [{grade_color}]{score.grade}[/])\n"
                f"[dim]Target:[/] {result.repo_root}  |  "
                f"[dim]Duration:[/] {result.duration_seconds:.2f}s  |  "
                f"[dim]Findings:[/] {result.total_findings}"
            )
            self.console.print(
                Panel(
                    score_text,
                    title="🛡️ [bold cyan]RepoGuard Health Assessment[/]",
                    border_style="cyan",
                )
            )

            # 2. Category Breakdown Table
            cat_table = Table(
                title="Category Breakdown",
                show_header=True,
                header_style="bold magenta",
            )
            cat_table.add_column("Category", style="cyan", width=18)
            cat_table.add_column("Weight", justify="center", width=8)
            cat_table.add_column("Score", justify="right", width=8)
            cat_table.add_column("Deductions", justify="right", width=11)
            cat_table.add_column("Status", justify="center", width=12)
            cat_table.add_column("Notes", style="white")

            for cat, data in score.breakdown.items():
                cat_name = cat.value.replace("_", " ").title()
                score_style = (
                    "green" if data.score >= 80 else ("yellow" if data.score >= 60 else "red")
                )
                status_style = (
                    "green"
                    if data.status == "evaluated"
                    else ("yellow" if data.status == "unavailable" else "red")
                )

                cat_table.add_row(
                    cat_name,
                    f"{data.weight * 100:.0f}%",
                    f"[{score_style}]{data.score:.1f}[/]",
                    f"-{data.deductions:.0f} pts" if data.deductions > 0 else "0 pts",
                    f"[{status_style}]{data.status}[/]",
                    data.explanation,
                )

            self.console.print(cat_table)

        # 3. Findings Table
        if result.findings:
            findings_table = Table(
                title=f"Detected Findings ({len(result.findings)})",
                show_header=True,
                header_style="bold red",
            )
            findings_table.add_column("ID", style="bold cyan", width=9)
            findings_table.add_column("Severity", justify="center", width=10)
            findings_table.add_column("Category", style="yellow", width=14)
            findings_table.add_column("Location", style="white", width=24)
            findings_table.add_column("Description & Remediation", style="white")

            for f in result.findings:
                sev_style = {
                    "critical": "bold white on red",
                    "high": "bold red",
                    "medium": "bold yellow",
                    "low": "cyan",
                    "info": "dim",
                }.get(f.severity.value, "white")

                loc = f"{f.file_path or 'repository'}"
                if f.line_number:
                    loc = f"{loc}:{f.line_number}"

                desc_remed = f"[bold]{f.description}[/]\n[dim]Remediation: {f.remediation}[/]"
                if f.evidence:
                    desc_remed += f"\n[dim italic]Evidence: {f.evidence}[/]"

                findings_table.add_row(
                    f.id,
                    f"[{sev_style}]{f.severity.value.upper()}[/]",
                    f.category.value,
                    loc,
                    desc_remed,
                )

            self.console.print(findings_table)
        else:
            self.console.print(
                Panel(
                    "[bold green]No issues detected![/] All evaluated checks passed cleanly.",
                    title="Clean Repository",
                    border_style="green",
                )
            )

        # 4. Disclaimer Note
        if result.score:
            self.console.print(f"[dim italic]Note: {result.score.disclaimer}[/]\n")
