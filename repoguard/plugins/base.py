"""Base class for all RepoGuard analyzers (built-in and plugins)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from repoguard.core.findings import Category, Finding

if TYPE_CHECKING:
    from repoguard.core.context import ScanContext


class BaseAnalyzer(ABC):
    """Abstract base class that all built-in analyzers and external plugins must implement."""

    name: str = "base"
    description: str = "Base analyzer"
    category: Category = Category.CUSTOM
    version: str = "0.1.0"
    enabled: bool = True

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = config or {}

    @abstractmethod
    def analyze(self, context: ScanContext) -> list[Finding]:
        """Execute analysis against the repository context and return findings.

        Must never modify repository files.
        Must handle errors gracefully and never raise unhandled exceptions.
        """
        raise NotImplementedError("Analyzers must implement analyze()")

    def is_available(self, context: ScanContext) -> bool:
        """Check if analyzer can run in the current context (e.g. network requirements)."""
        return True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} category={self.category.value!r}>"
