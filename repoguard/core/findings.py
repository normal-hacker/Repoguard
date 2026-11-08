"""Finding model representing detected issues, vulnerabilities, and suggestions."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def level(self) -> int:
        """Numeric rank for severity comparison (higher = more severe)."""
        levels = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5,
        }
        return levels[self]

    def meets_threshold(self, threshold: Severity | str) -> bool:
        """Check if this severity is greater than or equal to threshold."""
        if isinstance(threshold, str):
            try:
                threshold = Severity(threshold.lower())
            except ValueError:
                return False
        return self.level >= threshold.level


class Category(StrEnum):
    DOCUMENTATION = "documentation"
    CODE_QUALITY = "code_quality"
    SECURITY = "security"
    DEPENDENCIES = "dependencies"
    TESTING = "testing"
    CICD = "cicd"
    CUSTOM = "custom"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(BaseModel):
    """An individual issue, vulnerability, or health finding detected during analysis."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    id: str = Field(..., description="Unique rule/finding code (e.g., DOC001, SEC004)")
    analyzer: str = Field(..., description="Name of the analyzer that produced this finding")
    category: Category = Field(..., description="Category of the finding")
    severity: Severity = Field(..., description="Severity level")
    description: str = Field(..., description="Clear human-readable description of the issue")
    file_path: str | None = Field(
        default=None,
        description="Relative file path where the issue was found (if applicable)",
    )
    line_number: int | None = Field(
        default=None,
        ge=1,
        description="Line number where the issue was found (if applicable)",
    )
    evidence: str | None = Field(
        default=None,
        description="Non-sensitive code snippet or evidence string. Secrets MUST be masked.",
    )
    remediation: str = Field(..., description="Specific recommendation on how to resolve the issue")
    confidence: Confidence = Field(default=Confidence.HIGH, description="Confidence in finding")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary additional context"
    )

    @field_validator("file_path", mode="before")
    @classmethod
    def normalize_file_path(cls, v: Any) -> str | None:
        if v is None:
            return None
        if isinstance(v, Path):
            return v.as_posix()
        return str(v).replace("\\", "/")

    @property
    def fingerprint(self) -> str:
        """Generate a deterministic fingerprint hash to prevent double-counting."""
        norm_desc = " ".join(self.description.strip().split())
        raw = f"{self.id}|{self.file_path or ''}|{self.line_number or ''}|{norm_desc}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def __hash__(self) -> int:
        return hash(self.fingerprint)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return False
        return self.fingerprint == other.fingerprint
