"""CLI command tests for RepoGuard."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from repoguard import __version__
from repoguard.cli import app


def test_cli_version_flag(cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "repoguard" in result.output
    assert __version__ in result.output


def test_cli_version_command(cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output
    assert "Analyze. Detect. Improve." in result.output
    assert "MIT" in result.output


def test_cli_help(cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Analyze. Detect. Improve." in result.output
    assert "scan" in result.output
    assert "plugins" in result.output
    assert "config" in result.output


def test_cli_config_init(cli_runner: CliRunner, temp_repo: Path) -> None:
    result = cli_runner.invoke(app, ["config", "init", "--dir", str(temp_repo)])
    assert result.exit_code == 0
    assert "Success" in result.output
    created_file = temp_repo / ".repoguard.yml"
    assert created_file.is_file()

    # Re-running without --force should fail
    re_run = cli_runner.invoke(app, ["config", "init", "--dir", str(temp_repo)])
    assert re_run.exit_code == 1
    assert "already exists" in re_run.output

    # Re-running with --force should succeed
    forced_run = cli_runner.invoke(app, ["config", "init", "--dir", str(temp_repo), "--force"])
    assert forced_run.exit_code == 0
    assert "Success" in forced_run.output


def test_cli_plugins_list(cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0
    assert "Installed RepoGuard Plugins" in result.output


def test_cli_plugins_info_missing(cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(app, ["plugins", "info", "nonexistent-plugin"])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_cli_scan_basic(cli_runner: CliRunner, temp_repo: Path) -> None:
    # On an empty repo, high findings (missing README/tests) trigger exit code 1 under default thresholds
    result = cli_runner.invoke(app, ["scan", str(temp_repo)])
    assert result.exit_code == 1
    assert "RepoGuard Health Assessment" in result.output
    assert "Category Breakdown" in result.output
    assert "Detected Findings" in result.output
    assert "DOC001" in result.output


def test_cli_scan_passing_with_relaxed_threshold(cli_runner: CliRunner, temp_repo: Path) -> None:
    # When fail-on is set to critical and min-score is 0, high findings do not trigger failure
    result = cli_runner.invoke(
        app, ["scan", str(temp_repo), "--fail-on", "critical", "--min-score", "0"]
    )
    assert result.exit_code == 0
    assert "RepoGuard Health Assessment" in result.output
    assert "Category Breakdown" in result.output


def test_cli_scan_with_options(cli_runner: CliRunner, temp_repo: Path) -> None:
    result = cli_runner.invoke(
        app,
        [
            "scan",
            str(temp_repo),
            "--format",
            "json",
            "--no-network",
            "--exclude",
            "legacy/*",
            "--fail-on",
            "critical",
        ],
    )
    assert result.exit_code == 0
    assert '"enabled": false' in result.output
    assert '"legacy/*"' in result.output
    assert '"fail_on_severity": "critical"' in result.output
