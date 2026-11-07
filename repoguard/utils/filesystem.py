"""Filesystem safety utilities, path traversal guards, and file helpers."""

from __future__ import annotations

import fnmatch
from pathlib import Path

# Sensible default exclusion patterns across ecosystems
DEFAULT_EXCLUSIONS: list[str] = [
    ".git",
    ".git/*",
    ".venv",
    ".venv/*",
    "venv",
    "venv/*",
    "node_modules",
    "node_modules/*",
    "__pycache__",
    "__pycache__/*",
    "*.pyc",
    "*.pyo",
    ".pytest_cache",
    ".pytest_cache/*",
    ".ruff_cache",
    ".ruff_cache/*",
    ".mypy_cache",
    ".mypy_cache/*",
    ".tox",
    ".tox/*",
    "dist",
    "dist/*",
    "build",
    "build/*",
    ".eggs",
    ".eggs/*",
    "*.egg-info",
    "*.egg-info/*",
    ".DS_Store",
    ".repoguard_cache",
    ".repoguard_cache/*",
]

DEFAULT_MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB safety cap for deep scanning


class SecurityPathTraversalError(ValueError):
    """Raised when a path escapes the repository boundary."""


def safe_resolve_path(base_dir: Path, target: str | Path) -> Path:
    """Resolve a target path relative to base_dir, preventing path traversal attacks.

    Raises SecurityPathTraversalError if resolved path is not within base_dir.
    """
    base_resolved = base_dir.resolve()
    target_path = Path(target)
    if target_path.is_absolute():
        resolved = target_path.resolve()
    else:
        resolved = (base_resolved / target_path).resolve()

    try:
        resolved.relative_to(base_resolved)
    except ValueError as err:
        raise SecurityPathTraversalError(
            f"Path traversal detected: '{target}' resolves outside repository root '{base_dir}'"
        ) from err

    return resolved


def is_path_excluded(
    path: Path,
    base_dir: Path,
    user_exclusions: list[str] | None = None,
) -> bool:
    """Check if a path matches default or user-provided exclusion patterns.

    Matching is tested against the relative POSIX path, filename, and directory components.
    """
    try:
        rel_path = path.resolve().relative_to(base_dir.resolve()).as_posix()
    except ValueError:
        return True

    patterns = list(DEFAULT_EXCLUSIONS)
    if user_exclusions:
        patterns.extend(user_exclusions)

    parts = rel_path.split("/")
    name = path.name

    for pattern in patterns:
        norm_pattern = pattern.rstrip("/")
        if fnmatch.fnmatch(rel_path, norm_pattern):
            return True
        if fnmatch.fnmatch(name, norm_pattern):
            return True
        for part in parts:
            if fnmatch.fnmatch(part, norm_pattern):
                return True

    return False


def is_binary_file(file_path: Path, chunk_size: int = 1024) -> bool:
    """Detect if a file is likely binary by checking for null bytes in initial chunk."""
    try:
        with file_path.open("rb") as f:
            chunk = f.read(chunk_size)
            return b"\x00" in chunk
    except OSError:
        return True


def read_text_safe(
    file_path: Path,
    max_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    encoding: str = "utf-8",
) -> str | None:
    """Safely read text file with size limit and binary protection.

    Returns None if the file exceeds size limit, is binary, or cannot be decoded.
    """
    try:
        stat = file_path.stat()
        if stat.st_size > max_bytes:
            return None
        if is_binary_file(file_path):
            return None
        return file_path.read_text(encoding=encoding, errors="replace")
    except (OSError, UnicodeDecodeError):
        return None
