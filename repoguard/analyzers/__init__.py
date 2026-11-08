"""Built-in analyzers for RepoGuard."""

from __future__ import annotations

from repoguard.analyzers.cicd import CiCdAnalyzer
from repoguard.analyzers.code_quality import CodeQualityAnalyzer
from repoguard.analyzers.dependencies import DependencyAnalyzer
from repoguard.analyzers.documentation import DocumentationAnalyzer
from repoguard.analyzers.security import SecurityAnalyzer
from repoguard.analyzers.testing import TestingAnalyzer
from repoguard.core.registry import registry

# Automatically register built-in analyzers
registry.register(DocumentationAnalyzer, overwrite=True)
registry.register(DependencyAnalyzer, overwrite=True)
registry.register(TestingAnalyzer, overwrite=True)
registry.register(SecurityAnalyzer, overwrite=True)
registry.register(CodeQualityAnalyzer, overwrite=True)
registry.register(CiCdAnalyzer, overwrite=True)

__all__ = [
    "CiCdAnalyzer",
    "CodeQualityAnalyzer",
    "DependencyAnalyzer",
    "DocumentationAnalyzer",
    "SecurityAnalyzer",
    "TestingAnalyzer",
]
