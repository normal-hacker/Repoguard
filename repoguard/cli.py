"""RepoGuard Command-Line Interface."""

from __future__ import annotations

import platform
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from repoguard import __app_name__, __version__
from repoguard.config import RepoGuardConfig
from repoguard.utils.filesystem import SecurityPathTraversalError, safe_resolve_path

app = typer.Typer(
    name=__app_name__,
    help="RepoGuard - Open-Source Repository Health Analyzer. Analyze. Detect. Improve.",
    add_completion=False,
    no_args_is_help=True,
)

plugins_app = typer.Typer(
    name="plugins",
    help="Inspect and manage RepoGuard analyzer plugins.",
    no_args_is_help=True,
)
app.add_typer(plugins_app, name="plugins")

config_app = typer.Typer(
    name="config",
    help="Manage RepoGuard configuration files.",
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")

console = Console()
err_console = Console(stderr=True)


class OutputFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "markdown"


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]{__app_name__}[/] version [bold green]{__version__}[/]")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-v",
            help="Show the application version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """RepoGuard: Analyze. Detect. Improve."""


@app.command(name="version")
def version_command() -> None:
    """Display RepoGuard version, runtime environment, and platform details."""
    table = Table(
        title="RepoGuard System Information", show_header=True, header_style="bold magenta"
    )
    table.add_column("Component", style="cyan", width=20)
    table.add_column("Details", style="green")

    table.add_row("RepoGuard Version", __version__)
    table.add_row("Python Version", sys.version.split()[0])
    table.add_row("Python Executable", sys.executable)
    table.add_row("Platform", platform.platform())
    table.add_row("License", "MIT")
    table.add_row("Tagline", "Analyze. Detect. Improve.")

    console.print(table)


@config_app.command(name="init")
def config_init_command(
    output_dir: Annotated[
        Path,
        typer.Option(
            "--dir",
            "-d",
            help="Directory where .repoguard.yml should be initialized.",
        ),
    ] = Path("."),
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing configuration file if present.",
        ),
    ] = False,
) -> None:
    """Initialize a default .repoguard.yml configuration file."""
    target_file = output_dir / ".repoguard.yml"
    if target_file.exists() and not force:
        err_console.print(
            f"[bold red]Error:[/] Configuration file already exists at [yellow]{target_file}[/]. "
            "Use [bold cyan]--force[/] to overwrite."
        )
        raise typer.Exit(code=1)

    cfg = RepoGuardConfig()
    try:
        if target_file.exists() and force:
            target_file.unlink()
        cfg.save_default_yaml(target_file)
        console.print(
            f"[bold green]Success:[/] Generated default configuration at [bold cyan]{target_file}[/]"
        )
    except Exception as e:
        err_console.print(f"[bold red]Failed to write configuration:[/] {e}")
        raise typer.Exit(code=1) from e


@plugins_app.command(name="list")
def plugins_list_command() -> None:
    """List all registered RepoGuard plugins."""
    # In Stage 1, we provide the CLI foundation with discovery hook
    # Plugin manager implementation will be populated in Stage 7
    try:
        from repoguard.plugins.discovery import discover_plugins

        plugins = discover_plugins()
    except (ImportError, ModuleNotFoundError):
        plugins = []

    table = Table(title="Installed RepoGuard Plugins", show_header=True, header_style="bold blue")
    table.add_column("Plugin Name", style="cyan", width=25)
    table.add_column("Version", style="magenta", width=12)
    table.add_column("Description", style="white")

    if not plugins:
        table.add_row("None", "-", "No external plugins currently registered.")
    else:
        for p in plugins:
            table.add_row(p.name, getattr(p, "version", "unknown"), getattr(p, "description", ""))

    console.print(table)


@plugins_app.command(name="info")
def plugins_info_command(
    plugin_name: Annotated[str, typer.Argument(help="Name of the plugin to inspect.")],
) -> None:
    """Display detailed metadata for a registered plugin."""
    try:
        from repoguard.plugins.discovery import get_plugin_info

        info = get_plugin_info(plugin_name)
    except (ImportError, ModuleNotFoundError):
        info = None

    if not info:
        err_console.print(f"[bold red]Error:[/] Plugin [yellow]'{plugin_name}'[/] not found.")
        raise typer.Exit(code=1)

    panel = Panel(
        f"[bold]Name:[/] {info.get('name')}\n"
        f"[bold]Version:[/] {info.get('version', 'unknown')}\n"
        f"[bold]Description:[/] {info.get('description', '')}\n"
        f"[bold]Author:[/] {info.get('author', 'Unknown')}\n"
        f"[bold]Entry Point:[/] {info.get('entry_point', '')}",
        title=f"Plugin Info: {plugin_name}",
        border_style="cyan",
    )
    console.print(panel)


@app.command(name="scan")
def scan_command(
    target_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the repository or directory to analyze.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
        ),
    ] = Path("."),
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Report output format: terminal, json, or markdown.",
            case_sensitive=False,
        ),
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write report output directly to a file.",
        ),
    ] = None,
    no_network: Annotated[
        bool,
        typer.Option(
            "--no-network",
            help="Disable all external network calls (registry lookups, OSV API).",
        ),
    ] = False,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude",
            "-e",
            help="Additional file or directory patterns to exclude from scanning.",
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Explicit path to RepoGuard configuration file.",
        ),
    ] = None,
    min_score: Annotated[
        float | None,
        typer.Option(
            "--min-score",
            help="Minimum overall repository score required (0-100). Exits with code 1 if failed.",
        ),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Fail if any finding meets or exceeds this severity (critical, high, medium, low).",
        ),
    ] = None,
) -> None:
    """Analyze a repository for health, security, code quality, and best practices."""
    # Validate target directory
    try:
        resolved_target = safe_resolve_path(target_path, ".")
    except SecurityPathTraversalError as e:
        err_console.print(f"[bold red]Security Error:[/] {e}")
        raise typer.Exit(code=1) from e

    # Load configuration
    try:
        cfg = RepoGuardConfig.load(config_path=config, repo_root=resolved_target)
    except Exception as e:
        err_console.print(f"[bold red]Configuration Error:[/] {e}")
        raise typer.Exit(code=1) from e

    # Apply CLI overrides
    if no_network:
        cfg.network.enabled = False
    if exclude:
        cfg.exclusions.extend(exclude)
    if min_score is not None:
        cfg.thresholds.min_score = min_score
    if fail_on is not None:
        cfg.thresholds.fail_on_severity = fail_on  # type: ignore

    # Execute scanning engine
    from repoguard.core.scanner import RepoScanner

    with console.status("[bold green]Scanning repository...[/]", spinner="dots"):
        scanner = RepoScanner(repo_root=resolved_target, config=cfg)
        result = scanner.run()

    # Format output
    if format == OutputFormat.JSON:
        output_content = result.model_dump_json(indent=2)
        if output:
            output.write_text(output_content, encoding="utf-8")
            console.print(f"[bold green]Report written to:[/] {output}")
        else:
            console.print(output_content)
    elif format == OutputFormat.MARKDOWN:
        lines = [
            "# RepoGuard Scan Report",
            "",
            f"- **Target**: `{result.repo_root}`",
            f"- **Duration**: {result.duration_seconds:.2f}s",
            f"- **Total Findings**: {result.total_findings}",
            f"- **Timestamp**: {result.timestamp.isoformat()}",
            "",
            "## Analyzer Summary",
            "",
            "| Analyzer | Category | Status | Findings | Duration |",
            "|---|---|---|---|---|",
        ]
        for a_res in result.analyzer_results.values():
            lines.append(
                f"| {a_res.name} | {a_res.category} | {a_res.status} | {a_res.findings_count} | {a_res.duration_seconds:.3f}s |"
            )
        if not result.analyzer_results:
            lines.append("| *None* | - | - | - | - |")
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        if not result.findings:
            lines.append("No issues detected.")
        else:
            for f in result.findings:
                lines.append(f"### [{f.severity.upper()}] {f.id}: {f.description}")
                lines.append(f"- **Category**: {f.category.value}")
                lines.append(
                    f"- **File**: `{f.file_path or 'N/A'}` (line {f.line_number or 'N/A'})"
                )
                lines.append(f"- **Remediation**: {f.remediation}")
                lines.append("")
        markdown_content = "\n".join(lines)
        if output:
            output.write_text(markdown_content, encoding="utf-8")
            console.print(f"[bold green]Report written to:[/] {output}")
        else:
            console.print(markdown_content)
    else:
        # Rich Terminal Output
        table = Table(
            title=f"RepoGuard Scan Summary (Duration: {result.duration_seconds:.2f}s)",
            show_header=True,
            header_style="bold blue",
        )
        table.add_column("Analyzer", style="cyan")
        table.add_column("Category", style="yellow")
        table.add_column("Status", style="green")
        table.add_column("Findings", justify="right")
        table.add_column("Duration", justify="right")

        if not result.analyzer_results:
            table.add_row("No analyzers registered", "-", "-", "0", "0.00s")
        else:
            for a_res in result.analyzer_results.values():
                status_style = (
                    "green"
                    if a_res.status == "success"
                    else ("yellow" if a_res.status == "skipped" else "red")
                )
                table.add_row(
                    a_res.name,
                    a_res.category,
                    f"[{status_style}]{a_res.status}[/]",
                    str(a_res.findings_count),
                    f"{a_res.duration_seconds:.3f}s",
                )
        console.print(table)

        if result.findings:
            findings_table = Table(
                title="Detected Findings", show_header=True, header_style="bold red"
            )
            findings_table.add_column("ID", style="bold cyan", width=10)
            findings_table.add_column("Severity", style="magenta", width=10)
            findings_table.add_column("Category", style="yellow", width=14)
            findings_table.add_column("File:Line", style="white", width=25)
            findings_table.add_column("Description", style="white")

            for f in result.findings:
                loc = f"{f.file_path or 'repo'}"
                if f.line_number:
                    loc = f"{loc}:{f.line_number}"
                findings_table.add_row(
                    f.id,
                    f.severity.value.upper(),
                    f.category.value,
                    loc,
                    f.description,
                )
            console.print(findings_table)
        else:
            console.print(
                Panel(
                    f"Repository: [cyan]{result.repo_root}[/]\n"
                    f"Total files checked: [blue]{len(scanner.context.files)}[/]\n"
                    f"Findings: [green]0 issues detected[/]",
                    title="[bold green]Scan Completed Successfully[/]",
                    border_style="green",
                )
            )

        if output:
            output.write_text(result.model_dump_json(indent=2), encoding="utf-8")
            console.print(f"[bold green]Raw JSON report written to:[/] {output}")

    raise typer.Exit(code=result.exit_code)
