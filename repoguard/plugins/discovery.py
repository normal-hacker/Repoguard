"""Plugin discovery via Python entry points."""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

from pydantic import BaseModel

from repoguard.core.findings import Category
from repoguard.core.registry import (
    AnalyzerRegistry,
    DuplicateAnalyzerError,
    InvalidAnalyzerError,
)
from repoguard.core.registry import registry as default_registry

ENTRY_POINT_GROUP = "repoguard.plugins"


class PluginMetadata(BaseModel):
    """Metadata describing an installed RepoGuard plugin."""

    name: str
    version: str = "unknown"
    description: str = ""
    author: str = "Unknown"
    category: str = "custom"
    entry_point: str
    is_builtin: bool = False


def discover_plugins(
    target_registry: AnalyzerRegistry | None = None,
) -> list[PluginMetadata]:
    """Discover third-party plugins registered under 'repoguard.plugins' entry points.

    Validates plugin classes and registers them into the target registry.
    Safely catches any import or initialization errors to prevent scan crashes.
    """
    from repoguard.plugins.base import BaseAnalyzer

    reg = target_registry or default_registry
    discovered: list[PluginMetadata] = []

    # Include built-in analyzers in discovery listing
    for analyzer_cls in reg.list_all():
        discovered.append(
            PluginMetadata(
                name=analyzer_cls.name,
                version=getattr(analyzer_cls, "version", "1.0.0"),
                description=getattr(analyzer_cls, "description", ""),
                category=getattr(analyzer_cls, "category", Category.CUSTOM).value,
                entry_point=f"{analyzer_cls.__module__}:{analyzer_cls.__name__}",
                is_builtin=True,
            )
        )

    # Discover external plugins via standard Python entry points
    try:
        eps = entry_points(group=ENTRY_POINT_GROUP)
    except Exception:
        return discovered

    for ep in eps:
        try:
            plugin_cls = ep.load()
            if not isinstance(plugin_cls, type) or not issubclass(plugin_cls, BaseAnalyzer):
                continue

            metadata = PluginMetadata(
                name=plugin_cls.name,
                version=getattr(plugin_cls, "version", "0.1.0"),
                description=getattr(plugin_cls, "description", ""),
                category=(
                    plugin_cls.category.value
                    if isinstance(plugin_cls.category, Category)
                    else str(plugin_cls.category)
                ),
                entry_point=f"{ep.value}",
                is_builtin=False,
            )

            # Register if not already present
            if reg.get(plugin_cls.name) is None:
                reg.register(plugin_cls)

            discovered.append(metadata)

        except (ImportError, AttributeError, DuplicateAnalyzerError, InvalidAnalyzerError):
            # External plugin failure should not crash scan or discovery
            continue

    return discovered


def get_plugin_info(plugin_name: str) -> dict[str, Any] | None:
    """Retrieve metadata dictionary for a specific registered or discovered plugin."""
    plugins = discover_plugins()
    for p in plugins:
        if p.name.lower() == plugin_name.lower():
            return p.model_dump()
    return None
