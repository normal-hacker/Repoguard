"""Tests for RepoGuard configuration validation and loading."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoguard.config import RepoGuardConfig, ScoringWeights


def test_default_config_valid() -> None:
    config = RepoGuardConfig()
    assert config.version == 1
    assert config.network.enabled is True
    assert config.thresholds.min_score == 70.0
    assert config.thresholds.fail_on_severity == "high"
    assert config.scoring_weights.documentation == 0.15
    assert config.scoring_weights.code_quality == 0.25
    assert config.scoring_weights.security == 0.25
    assert config.scoring_weights.dependencies == 0.15
    assert config.scoring_weights.testing == 0.10
    assert config.scoring_weights.cicd == 0.10


def test_scoring_weights_validation_failure() -> None:
    with pytest.raises(ValueError, match="Scoring weights must sum to 1.0"):
        ScoringWeights(
            documentation=0.5,
            code_quality=0.5,
            security=0.5,
            dependencies=0.1,
            testing=0.1,
            cicd=0.1,
        )


def test_save_and_load_yaml(temp_repo: Path) -> None:
    config = RepoGuardConfig(exclusions=["dist/*", "vendor/*"])
    target_yaml = temp_repo / ".repoguard.yml"
    config.save_default_yaml(target_yaml)

    assert target_yaml.is_file()
    loaded = RepoGuardConfig.from_file(target_yaml)
    assert loaded.exclusions == ["dist/*", "vendor/*"]
    assert loaded.thresholds.min_score == 70.0


def test_save_existing_file_error(temp_repo: Path) -> None:
    target = temp_repo / ".repoguard.yml"
    target.write_text("existing: true", encoding="utf-8")
    config = RepoGuardConfig()
    with pytest.raises(FileExistsError):
        config.save_default_yaml(target)


def test_load_json(temp_repo: Path) -> None:
    target_json = temp_repo / ".repoguard.json"
    data = {
        "version": 1,
        "exclusions": ["temp/*"],
        "thresholds": {"min_score": 85.0, "fail_on_severity": "critical"},
    }
    target_json.write_text(json.dumps(data), encoding="utf-8")

    loaded = RepoGuardConfig.from_file(target_json)
    assert loaded.thresholds.min_score == 85.0
    assert loaded.thresholds.fail_on_severity == "critical"
    assert loaded.exclusions == ["temp/*"]


def test_load_from_pyproject_toml(sample_pyproject: Path, temp_repo: Path) -> None:
    loaded = RepoGuardConfig.load(repo_root=temp_repo)
    assert loaded.exclusions == ["tests/fixtures/*", "legacy/*"]
    assert loaded.thresholds.min_score == 80.0
    assert loaded.scoring_weights.documentation == 0.20


def test_load_nonexistent_file() -> None:
    with pytest.raises(FileNotFoundError):
        RepoGuardConfig.from_file(Path("/nonexistent/file.yml"))
