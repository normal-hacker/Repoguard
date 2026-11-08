"""ScanContext provides execution context and repository file querying for analyzers."""

from __future__ import annotations

import fnmatch
from pathlib import Path

from repoguard.config import RepoGuardConfig
from repoguard.utils.filesystem import (
    SecurityPathTraversalError,
    is_path_excluded,
    read_text_safe,
    safe_resolve_path,
)


class ScanContext:
    """Execution context provided to analyzers during repository analysis.

    Provides safe file access, exclusion filtering, git integration, and configuration.
    """

    def __init__(
        self,
        repo_root: Path,
        config: RepoGuardConfig | None = None,
        network_enabled: bool | None = None,
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.config = config or RepoGuardConfig()
        self.network_enabled = (
            network_enabled if network_enabled is not None else self.config.network.enabled
        )

        # Initialize Git integration safely if git directory exists
        self._git_repo = None
        self._init_git()

        # Cached file collection respecting exclusions
        self._files: list[Path] | None = None

    def _init_git(self) -> None:
        """Attempt to initialize Git repository safely."""
        try:
            import git

            if (self.repo_root / ".git").is_dir():
                self._git_repo = git.Repo(self.repo_root)
        except Exception:
            self._git_repo = None

    @property
    def git_repo(self):
        """GitPython Repo instance, or None if not a valid git repository."""
        return self._git_repo

    @property
    def is_git_repo(self) -> bool:
        """True if the target is a valid git repository."""
        return self._git_repo is not None

    @property
    def files(self) -> list[Path]:
        """List all non-excluded files in the repository (cached)."""
        if self._files is None:
            collected: list[Path] = []
            for path in self.repo_root.rglob("*"):
                if path.is_file() and not is_path_excluded(
                    path,
                    base_dir=self.repo_root,
                    user_exclusions=self.config.exclusions,
                ):
                    collected.append(path)
            self._files = sorted(collected)
        return self._files

    def get_relative_path(self, file_path: Path | str) -> str:
        """Get POSIX-style path relative to the repository root."""
        path = Path(file_path) if isinstance(file_path, str) else file_path
        try:
            resolved = safe_resolve_path(self.repo_root, path)
            return resolved.relative_to(self.repo_root).as_posix()
        except (SecurityPathTraversalError, ValueError):
            return path.as_posix()

    def list_files(
        self,
        extension: str | None = None,
        pattern: str | None = None,
    ) -> list[Path]:
        """Filter repository files by extension (e.g. '.py') or glob pattern (e.g. '*.md')."""
        result = self.files
        if extension:
            ext = extension if extension.startswith(".") else f".{extension}"
            result = [f for f in result if f.suffix.lower() == ext.lower()]
        if pattern:
            result = [f for f in result if fnmatch.fnmatch(f.name, pattern)]
        return result

    def find_files_by_name(self, names: list[str]) -> list[Path]:
        """Find all files in repository whose filename matches one of the given names."""
        name_set = {n.lower() for n in names}
        return [f for f in self.files if f.name.lower() in name_set]

    def has_file(self, relative_path: str) -> bool:
        """Check if a file exists relative to the repository root without escaping bounds."""
        try:
            target = safe_resolve_path(self.repo_root, relative_path)
            return target.is_file()
        except SecurityPathTraversalError:
            return False

    def read_file(
        self,
        file_path: Path | str,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        """Safely read text content of a file within repository bounds."""
        try:
            resolved = safe_resolve_path(self.repo_root, file_path)
            return read_text_safe(resolved, max_bytes=max_bytes)
        except SecurityPathTraversalError:
            return None

    def read_file_lines(
        self,
        file_path: Path | str,
        max_bytes: int = 1_000_000,
    ) -> list[str] | None:
        """Safely read lines from a file within repository bounds."""
        content = self.read_file(file_path, max_bytes=max_bytes)
        if content is None:
            return None
        return content.splitlines()
