"""Configuration models, loading, and defaults for RepoGuard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

# Default config filenames searched in repository root
CONFIG_FILENAMES = [
    ".repoguard.yml",
    ".repoguard.yaml",
    ".repoguard.json",
    "pyproject.toml",
]

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]


class ScoringWeights(BaseModel):
    """Category weights for repository health score calculation (sum must be 1.0)."""

    documentation: float = Field(default=0.15, ge=0.0, le=1.0)
    code_quality: float = Field(default=0.25, ge=0.0, le=1.0)
    security: float = Field(default=0.25, ge=0.0, le=1.0)
    dependencies: float = Field(default=0.15, ge=0.0, le=1.0)
    testing: float = Field(default=0.10, ge=0.0, le=1.0)
    cicd: float = Field(default=0.10, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_weights_sum(self) -> ScoringWeights:
        total = (
            self.documentation
            + self.code_quality
            + self.security
            + self.dependencies
            + self.testing
            + self.cicd
        )
        if abs(total - 1.0) > 0.005:
            raise ValueError(f"Scoring weights must sum to 1.0 (current sum: {total:.3f})")
        return self


class NetworkConfig(BaseModel):
    """Network-related settings for registry lookups and vulnerability APIs."""

    enabled: bool = True
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    max_retries: int = Field(default=2, ge=0, le=5)


class ThresholdsConfig(BaseModel):
    """Quality and security thresholds for CI/CD gates."""

    min_score: float = Field(default=70.0, ge=0.0, le=100.0)
    fail_on_severity: SeverityLevel | None = "high"


class CodeQualityLimits(BaseModel):
    """Configurable thresholds for code quality analyzer."""

    max_file_lines: int = Field(default=500, ge=50)
    max_function_lines: int = Field(default=50, ge=10)
    max_cyclomatic_complexity: int = Field(default=10, ge=1)
    max_function_arguments: int = Field(default=6, ge=1)


class RepoGuardConfig(BaseModel):
    """Root configuration for RepoGuard."""

    version: int = 1
    scoring_weights: ScoringWeights = Field(default_factory=ScoringWeights)
    thresholds: ThresholdsConfig = Field(default_factory=ThresholdsConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    code_quality: CodeQualityLimits = Field(default_factory=CodeQualityLimits)
    exclusions: list[str] = Field(default_factory=list)
    plugins: dict[str, dict[str, Any]] = Field(default_factory=dict)
    analyzers: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @field_validator("exclusions")
    @classmethod
    def clean_exclusions(cls, v: list[str]) -> list[str]:
        return [item.strip() for item in v if item.strip()]

    @classmethod
    def find_config_file(cls, repo_root: Path) -> Path | None:
        """Find the first matching configuration file in repo_root."""
        for name in CONFIG_FILENAMES:
            candidate = repo_root / name
            if candidate.is_file():
                return candidate
        return None

    @classmethod
    def from_file(cls, config_path: Path) -> RepoGuardConfig:
        """Load configuration from a specific file (.yml, .yaml, .json, or pyproject.toml)."""
        if not config_path.is_file():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        suffix = config_path.suffix.lower()
        content = config_path.read_text(encoding="utf-8")

        if suffix in [".yml", ".yaml"]:
            data = yaml.safe_load(content) or {}
        elif suffix == ".json":
            data = json.loads(content)
        elif suffix == ".toml" or config_path.name == "pyproject.toml":
            import tomllib  # Python 3.11+ standard library

            toml_data = tomllib.loads(content)
            data = toml_data.get("tool", {}).get("repoguard", {})
        else:
            raise ValueError(f"Unsupported config format: {config_path.suffix}")

        return cls.model_validate(data)

    @classmethod
    def load(cls, config_path: Path | None = None, repo_root: Path = Path(".")) -> RepoGuardConfig:
        """Load configuration from specified path or auto-detect in repository root."""
        if config_path:
            return cls.from_file(config_path)

        detected = cls.find_config_file(repo_root)
        if detected:
            try:
                return cls.from_file(detected)
            except Exception as e:
                # Fallback to defaults with logged/handled issue if corrupted
                raise ValueError(f"Error loading configuration from {detected}: {e}") from e

        return cls()

    def to_yaml_string(self) -> str:
        """Serialize configuration to a clean, commented YAML string."""
        dumped = self.model_dump()
        header = (
            "# RepoGuard Configuration File\n"
            "# Analyze. Detect. Improve.\n"
            "# Documentation: https://github.com/repoguard/repoguard\n\n"
        )
        body = yaml.dump(dumped, sort_keys=False, default_flow_style=False)
        return header + body

    def save_default_yaml(self, destination: Path) -> Path:
        """Write default configuration file to destination."""
        if destination.exists():
            raise FileExistsError(f"Target configuration file already exists: {destination}")
        destination.write_text(self.to_yaml_string(), encoding="utf-8")
        return destination
