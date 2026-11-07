"""Tests for filesystem safety, path traversal prevention, and safe reading."""

from __future__ import annotations

from pathlib import Path

import pytest

from repoguard.utils.filesystem import (
    SecurityPathTraversalError,
    is_binary_file,
    is_path_excluded,
    read_text_safe,
    safe_resolve_path,
)


def test_safe_resolve_path_within_bounds(temp_repo: Path) -> None:
    subdir = temp_repo / "src" / "components"
    subdir.mkdir(parents=True)
    resolved = safe_resolve_path(temp_repo, "src/components")
    assert resolved == subdir


def test_safe_resolve_path_traversal_blocked(temp_repo: Path) -> None:
    with pytest.raises(SecurityPathTraversalError) as exc_info:
        safe_resolve_path(temp_repo, "../outside_file")
    assert "Path traversal detected" in str(exc_info.value)


def test_safe_resolve_path_absolute_outside_blocked(temp_repo: Path) -> None:
    outside = Path("/etc/passwd")
    with pytest.raises(SecurityPathTraversalError):
        safe_resolve_path(temp_repo, outside)


def test_is_path_excluded_default_patterns(temp_repo: Path) -> None:
    git_dir = temp_repo / ".git" / "config"
    node_modules = temp_repo / "node_modules" / "package" / "index.js"
    pycache = temp_repo / "src" / "__pycache__" / "test.cpython-311.pyc"
    normal_file = temp_repo / "src" / "main.py"

    assert is_path_excluded(git_dir, temp_repo) is True
    assert is_path_excluded(node_modules, temp_repo) is True
    assert is_path_excluded(pycache, temp_repo) is True
    assert is_path_excluded(normal_file, temp_repo) is False


def test_is_path_excluded_user_patterns(temp_repo: Path) -> None:
    custom_doc = temp_repo / "docs" / "generated" / "api.md"
    user_exclusions = ["docs/generated/*", "*.tmp"]
    assert is_path_excluded(custom_doc, temp_repo, user_exclusions=user_exclusions) is True


def test_is_binary_file(temp_repo: Path) -> None:
    text_file = temp_repo / "hello.txt"
    text_file.write_text("Hello, RepoGuard!", encoding="utf-8")
    assert is_binary_file(text_file) is False

    bin_file = temp_repo / "test.bin"
    bin_file.write_bytes(b"PNG\x00\x01\x02\x03")
    assert is_binary_file(bin_file) is True


def test_read_text_safe_size_limit(temp_repo: Path) -> None:
    large_file = temp_repo / "large.txt"
    # Create file exceeding limit
    large_file.write_bytes(b"a" * 1024)
    # Read with smaller max_bytes
    assert read_text_safe(large_file, max_bytes=500) is None
    # Read with adequate max_bytes
    content = read_text_safe(large_file, max_bytes=2048)
    assert content is not None
    assert len(content) == 1024


def test_read_text_safe_binary(temp_repo: Path) -> None:
    bin_file = temp_repo / "data.dat"
    bin_file.write_bytes(b"\x00\x01\x02\x03\x04")
    assert read_text_safe(bin_file) is None
