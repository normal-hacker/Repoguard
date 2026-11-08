"""Tests for ScanContext repository inspection and querying."""

from __future__ import annotations

from pathlib import Path

from repoguard.config import RepoGuardConfig
from repoguard.core.context import ScanContext


def test_context_file_discovery(temp_repo: Path) -> None:
    # Set up sample file structure
    (temp_repo / "src").mkdir()
    (temp_repo / "src" / "app.py").write_text("print('hello')", encoding="utf-8")
    (temp_repo / "README.md").write_text("# Project", encoding="utf-8")
    (temp_repo / ".git").mkdir()  # Should be excluded by default
    (temp_repo / ".git" / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)

    assert len(ctx.files) == 2
    rel_paths = [ctx.get_relative_path(f) for f in ctx.files]
    assert "src/app.py" in rel_paths
    assert "README.md" in rel_paths
    assert ".git/HEAD" not in rel_paths


def test_context_list_files_filter(temp_repo: Path) -> None:
    (temp_repo / "app.py").write_text("pass", encoding="utf-8")
    (temp_repo / "test.py").write_text("pass", encoding="utf-8")
    (temp_repo / "doc.md").write_text("# Hi", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    py_files = ctx.list_files(extension=".py")
    assert len(py_files) == 2

    md_files = ctx.list_files(extension="md")
    assert len(md_files) == 1

    pattern_files = ctx.list_files(pattern="test.*")
    assert len(pattern_files) == 1


def test_context_find_files_by_name(temp_repo: Path) -> None:
    (temp_repo / "README.md").write_text("# Readme", encoding="utf-8")
    (temp_repo / "LICENSE").write_text("MIT", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    found = ctx.find_files_by_name(["readme.md", "license"])
    assert len(found) == 2


def test_context_read_file_safe(temp_repo: Path) -> None:
    file = temp_repo / "sample.txt"
    file.write_text("Line 1\nLine 2\nLine 3", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    assert ctx.has_file("sample.txt") is True
    assert ctx.has_file("nonexistent.txt") is False

    content = ctx.read_file("sample.txt")
    assert content == "Line 1\nLine 2\nLine 3"

    lines = ctx.read_file_lines("sample.txt")
    assert lines == ["Line 1", "Line 2", "Line 3"]

    # Traversal attempt returns None / False
    assert ctx.has_file("../../etc/passwd") is False
    assert ctx.read_file("../../etc/passwd") is None


def test_context_respects_custom_exclusions(temp_repo: Path) -> None:
    (temp_repo / "src").mkdir()
    (temp_repo / "src" / "main.py").write_text("pass", encoding="utf-8")
    (temp_repo / "generated").mkdir()
    (temp_repo / "generated" / "gen.py").write_text("pass", encoding="utf-8")

    cfg = RepoGuardConfig(exclusions=["generated/*"])
    ctx = ScanContext(repo_root=temp_repo, config=cfg)

    rel_paths = [ctx.get_relative_path(f) for f in ctx.files]
    assert "src/main.py" in rel_paths
    assert "generated/gen.py" not in rel_paths
