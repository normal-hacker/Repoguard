"""Built-in analyzers for RepoGuard."""

from __future__ import annotations

from repoguard.analyzers.dependencies import DependencyAnalyzer
from repoguard.analyzers.documentation import DocumentationAnalyzer
from repoguard.analyzers.testing import TestingAnalyzer
from repoguard.core.registry import registry

# Automatically register built-in analyzers
registry.register(DocumentationAnalyzer, overwrite=True)
registry.register(DependencyAnalyzer, overwrite=True)
registry.register(TestingAnalyzer, overwrite=True)

__all__ = [
    "DependencyAnalyzer",
    "DocumentationAnalyzer",
    "TestingAnalyzer",
]
