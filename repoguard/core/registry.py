"""Analyzer registry managing built-in and external analyzer registrations."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

from repoguard.core.findings import Category

if TYPE_CHECKING:
    from repoguard.plugins.base import BaseAnalyzer


class DuplicateAnalyzerError(ValueError):
    """Raised when an analyzer with an existing name is registered."""


class InvalidAnalyzerError(TypeError):
    """Raised when an analyzer does not conform to the BaseAnalyzer interface."""


class AnalyzerRegistry:
    """Registry maintaining registered analyzers with duplicate detection and metadata validation."""

    def __init__(self) -> None:
        self._analyzers: dict[str, type[BaseAnalyzer]] = {}

    def register(self, analyzer_cls: type[BaseAnalyzer], overwrite: bool = False) -> None:
        """Register an analyzer class.

        Validates inheritance and metadata, and prevents accidental duplication.
        """
        from repoguard.plugins.base import BaseAnalyzer

        if not inspect.isclass(analyzer_cls) or not issubclass(analyzer_cls, BaseAnalyzer):
            raise InvalidAnalyzerError(
                f"Analyzer {analyzer_cls!r} must be a class inheriting from BaseAnalyzer"
            )

        name = getattr(analyzer_cls, "name", None)
        if not name or not isinstance(name, str) or not name.strip():
            raise InvalidAnalyzerError(
                f"Analyzer {analyzer_cls!r} must define a non-empty 'name' string"
            )

        name = name.strip()
        if name in self._analyzers and not overwrite:
            existing = self._analyzers[name]
            raise DuplicateAnalyzerError(
                f"Analyzer with name '{name}' is already registered: {existing!r}"
            )

        self._analyzers[name] = analyzer_cls

    def unregister(self, name: str) -> bool:
        """Remove an analyzer from the registry. Returns True if removed."""
        if name in self._analyzers:
            del self._analyzers[name]
            return True
        return False

    def get(self, name: str) -> type[BaseAnalyzer] | None:
        """Retrieve an analyzer class by name."""
        return self._analyzers.get(name)

    def list_all(self) -> list[type[BaseAnalyzer]]:
        """List all registered analyzer classes."""
        return list(self._analyzers.values())

    def list_by_category(self, category: Category | str) -> list[type[BaseAnalyzer]]:
        """List all analyzers belonging to a specific category."""
        target_cat = Category(category) if isinstance(category, str) else category
        return [
            cls for cls in self._analyzers.values() if getattr(cls, "category", None) == target_cat
        ]

    def clear(self) -> None:
        """Clear all registered analyzers."""
        self._analyzers.clear()


# Global default registry instance
registry = AnalyzerRegistry()
