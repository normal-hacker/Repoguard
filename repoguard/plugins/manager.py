"""Plugin manager managing lifecycle, configuration, and registry synchronization."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from repoguard.core.registry import AnalyzerRegistry
from repoguard.core.registry import registry as default_registry
from repoguard.plugins.discovery import PluginMetadata, discover_plugins, get_plugin_info

if TYPE_CHECKING:
    from repoguard.config import RepoGuardConfig


class PluginManager:
    """Orchestrates external plugin discovery, configuration injection, and registration."""

    def __init__(self, registry: AnalyzerRegistry | None = None) -> None:
        self.registry = registry or default_registry

    def load_plugins(self, config: RepoGuardConfig | None = None) -> list[PluginMetadata]:
        """Discover and load external plugins into the registry, applying configuration."""
        metadata_list = discover_plugins(target_registry=self.registry)
        return metadata_list

    def list_plugins(self) -> list[PluginMetadata]:
        """List all currently registered and available plugins."""
        return discover_plugins(target_registry=self.registry)

    def get_info(self, name: str) -> dict[str, Any] | None:
        """Get plugin details by name."""
        return get_plugin_info(name)
