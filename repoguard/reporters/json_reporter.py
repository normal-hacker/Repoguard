"""JSON report generator and schema validation for RepoGuard."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from repoguard.core.scanner import ScanResult


class JsonReporter:
    """Serializes scan results to JSON conforming to the RepoGuard report schema."""

    @staticmethod
    def render(result: ScanResult, indent: int = 2) -> str:
        """Render ScanResult as formatted JSON string."""
        return result.model_dump_json(indent=indent)

    @staticmethod
    def render_dict(result: ScanResult) -> dict[str, Any]:
        """Convert ScanResult to dictionary representation."""
        return json.loads(result.model_dump_json())

    @staticmethod
    def get_schema() -> dict[str, Any]:
        """Return JSON Schema for the ScanResult payload."""
        from repoguard.core.scanner import ScanResult

        return ScanResult.model_json_schema()
