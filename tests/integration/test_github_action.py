"""Tests for action.yml structure and GitHub Actions workflows."""

from __future__ import annotations

from pathlib import Path

import yaml


def test_action_yml_structure() -> None:
    action_file = Path(__file__).parent.parent.parent / "action.yml"
    assert action_file.is_file(), "action.yml must exist at repository root"

    content = action_file.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    assert data["name"] == "RepoGuard Health Analyzer"
    assert data["runs"]["using"] == "composite"

    # Inputs verification
    inputs = data.get("inputs", {})
    assert "min-score" in inputs
    assert "fail-on" in inputs
    assert "no-network" in inputs
    assert "output-json" in inputs
    assert "output-markdown" in inputs

    # Outputs verification
    outputs = data.get("outputs", {})
    assert "score" in outputs
    assert "grade" in outputs
    assert "findings-count" in outputs


def test_workflows_valid_yaml() -> None:
    workflows_dir = Path(__file__).parent.parent.parent / ".github" / "workflows"
    assert workflows_dir.is_dir()

    for wf in workflows_dir.glob("*.yml"):
        content = wf.read_text(encoding="utf-8")
        parsed = yaml.safe_load(content)
        assert isinstance(parsed, dict)
        assert "name" in parsed
        assert "jobs" in parsed
