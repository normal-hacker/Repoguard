"""Plugin architecture interfaces and discovery for RepoGuard."""

from __future__ import annotations

from repoguard.plugins.base import BaseAnalyzer
from repoguard.plugins.discovery import PluginMetadata, discover_plugins, get_plugin_info
from repoguard.plugins.manager import PluginManager

__all__ = [
    "BaseAnalyzer",
    "PluginManager",
    "PluginMetadata",
    "discover_plugins",
    "get_plugin_info",
]
