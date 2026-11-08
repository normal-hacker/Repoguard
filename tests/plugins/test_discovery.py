"""Tests for plugin discovery, entry point loading, and metadata inspection."""

from __future__ import annotations

from unittest.mock import MagicMock

from repoguard.core.findings import Category, Finding
from repoguard.core.registry import AnalyzerRegistry
from repoguard.plugins.base import BaseAnalyzer
from repoguard.plugins.discovery import discover_plugins, get_plugin_info
from repoguard.plugins.manager import PluginManager


class MockExternalAnalyzer(BaseAnalyzer):
    name = "mock_external"
    description = "Mock external third-party plugin"
    category = Category.CUSTOM
    version = "1.2.3"

    def analyze(self, context) -> list[Finding]:
        return []


def test_discover_builtin_plugins() -> None:
    plugins = discover_plugins()
    plugin_names = [p.name for p in plugins]

    assert "documentation" in plugin_names
    assert "security" in plugin_names
    assert "code_quality" in plugin_names
    assert "dependencies" in plugin_names
    assert "testing" in plugin_names
    assert "cicd" in plugin_names


def test_discover_external_entry_point(monkeypatch) -> None:
    mock_ep = MagicMock()
    mock_ep.value = "my_plugin.module:MockExternalAnalyzer"
    mock_ep.load.return_value = MockExternalAnalyzer

    def mock_entry_points(group=None):
        if group == "repoguard.plugins":
            return [mock_ep]
        return []

    import repoguard.plugins.discovery as disc_mod

    monkeypatch.setattr(disc_mod, "entry_points", mock_entry_points)

    custom_reg = AnalyzerRegistry()
    discovered = discover_plugins(target_registry=custom_reg)
    discovered_names = [p.name for p in discovered]

    assert "mock_external" in discovered_names
    assert custom_reg.get("mock_external") is MockExternalAnalyzer


def test_invalid_external_entry_point_handled_safely(monkeypatch) -> None:
    # Simulates an external plugin that fails during load
    bad_ep = MagicMock()
    bad_ep.load.side_effect = ImportError("Missing third-party dependency")

    def mock_entry_points(group=None):
        return [bad_ep]

    import repoguard.plugins.discovery as disc_mod

    monkeypatch.setattr(disc_mod, "entry_points", mock_entry_points)

    # Discovery should not raise an exception
    plugins = discover_plugins()
    assert isinstance(plugins, list)


def test_get_plugin_info() -> None:
    info = get_plugin_info("documentation")
    assert info is not None
    assert info["name"] == "documentation"
    assert info["category"] == "documentation"
    assert info["is_builtin"] is True

    missing_info = get_plugin_info("nonexistent_plugin_xyz")
    assert missing_info is None


def test_plugin_manager_lifecycle() -> None:
    pm = PluginManager()
    plugins = pm.list_plugins()
    assert len(plugins) >= 6
    info = pm.get_info("security")
    assert info is not None
    assert info["name"] == "security"
