"""Tests for AnalyzerRegistry, registration validation, and duplicate prevention."""

from __future__ import annotations

import pytest

from repoguard.core.findings import Category, Finding
from repoguard.core.registry import (
    AnalyzerRegistry,
    DuplicateAnalyzerError,
    InvalidAnalyzerError,
)
from repoguard.plugins.base import BaseAnalyzer


class ValidAnalyzer(BaseAnalyzer):
    name = "valid_test"
    description = "A valid test analyzer"
    category = Category.DOCUMENTATION

    def analyze(self, context) -> list[Finding]:
        return []


class AnotherAnalyzer(BaseAnalyzer):
    name = "another_test"
    description = "Another analyzer"
    category = Category.SECURITY

    def analyze(self, context) -> list[Finding]:
        return []


def test_registry_registration_and_retrieval() -> None:
    reg = AnalyzerRegistry()
    reg.register(ValidAnalyzer)

    retrieved = reg.get("valid_test")
    assert retrieved is ValidAnalyzer
    assert len(reg.list_all()) == 1


def test_registry_duplicate_prevention() -> None:
    reg = AnalyzerRegistry()
    reg.register(ValidAnalyzer)

    with pytest.raises(DuplicateAnalyzerError, match="already registered"):
        reg.register(ValidAnalyzer)

    # Overwrite allowed when explicitly set
    reg.register(ValidAnalyzer, overwrite=True)
    assert len(reg.list_all()) == 1


def test_registry_invalid_analyzer() -> None:
    reg = AnalyzerRegistry()

    class NotAnAnalyzer:
        name = "invalid"

    with pytest.raises(InvalidAnalyzerError, match="inheriting from BaseAnalyzer"):
        reg.register(NotAnAnalyzer)  # type: ignore[arg-type]

    class MissingName(BaseAnalyzer):
        name = ""

        def analyze(self, context) -> list[Finding]:
            return []

    with pytest.raises(InvalidAnalyzerError, match="non-empty 'name'"):
        reg.register(MissingName)


def test_registry_query_by_category() -> None:
    reg = AnalyzerRegistry()
    reg.register(ValidAnalyzer)
    reg.register(AnotherAnalyzer)

    doc_analyzers = reg.list_by_category(Category.DOCUMENTATION)
    assert doc_analyzers == [ValidAnalyzer]

    sec_analyzers = reg.list_by_category(Category.SECURITY)
    assert sec_analyzers == [AnotherAnalyzer]


def test_registry_unregister() -> None:
    reg = AnalyzerRegistry()
    reg.register(ValidAnalyzer)
    assert reg.unregister("valid_test") is True
    assert reg.unregister("valid_test") is False
    assert reg.get("valid_test") is None
