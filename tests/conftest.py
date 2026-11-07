"""Pytest fixtures for RepoGuard tests."""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
from typer.testing import CliRunner


@pytest.fixture
def cli_runner() -> CliRunner:
    """Typer CLI runner for isolated command testing."""
    return CliRunner()


@pytest.fixture
def temp_repo() -> Generator[Path, None, None]:
    """Provide a clean temporary directory for filesystem and repository tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir).resolve()
        yield repo_path


@pytest.fixture
def sample_pyproject(temp_repo: Path) -> Path:
    """Create a sample pyproject.toml with tool.repoguard configuration."""
    content = """
[project]
name = "sample-app"
version = "1.0.0"

[tool.repoguard]
version = 1
exclusions = ["tests/fixtures/*", "legacy/*"]

[tool.repoguard.scoring_weights]
documentation = 0.20
code_quality = 0.20
security = 0.20
dependencies = 0.20
testing = 0.10
cicd = 0.10

[tool.repoguard.thresholds]
min_score = 80.0
fail_on_severity = "high"
"""
    file_path = temp_repo / "pyproject.toml"
    file_path.write_text(content.strip(), encoding="utf-8")
    return file_path
