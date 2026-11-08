"""Tests for CodeQualityAnalyzer: function complexity, arguments, length, and wildcard imports."""

from __future__ import annotations

from pathlib import Path

from repoguard.analyzers.code_quality import CodeQualityAnalyzer
from repoguard.config import RepoGuardConfig
from repoguard.core.context import ScanContext


def test_wildcard_import_detection(temp_repo: Path) -> None:
    code_file = temp_repo / "module.py"
    code_file.write_text("from math import *\n\nprint(sqrt(4))\n", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = CodeQualityAnalyzer()
    findings = analyzer.analyze(ctx)

    wildcard_findings = [f for f in findings if f.id == "QUAL002"]
    assert len(wildcard_findings) == 1
    assert "math" in wildcard_findings[0].description


def test_excessive_function_arguments(temp_repo: Path) -> None:
    code_file = temp_repo / "args_test.py"
    # Function with 8 arguments (limit is 6)
    code_file.write_text(
        "def big_func(a, b, c, d, e, f, g, h):\n    return a + b\n", encoding="utf-8"
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = CodeQualityAnalyzer()
    findings = analyzer.analyze(ctx)

    arg_findings = [f for f in findings if f.id == "QUAL004"]
    assert len(arg_findings) == 1
    assert "8 > 6" in arg_findings[0].description


def test_high_cyclomatic_complexity(temp_repo: Path) -> None:
    code_file = temp_repo / "complex.py"
    # Create function with complexity > 10
    code = """def complex_decision(x, y, z):
    if x > 1:
        pass
    if x > 2:
        pass
    if x > 3:
        pass
    if y > 1:
        pass
    if y > 2:
        pass
    if y > 3:
        pass
    if z > 1:
        pass
    if z > 2:
        pass
    if z > 3:
        pass
    if z > 4:
        pass
    if z > 5:
        pass
    return True
"""
    code_file.write_text(code, encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = CodeQualityAnalyzer()
    findings = analyzer.analyze(ctx)

    complex_findings = [f for f in findings if f.id == "QUAL005"]
    assert len(complex_findings) == 1
    assert "complex_decision" in complex_findings[0].description


def test_large_file_detection(temp_repo: Path) -> None:
    code_file = temp_repo / "huge_file.py"
    # Write 60 lines with config max_file_lines = 50
    code_file.write_text("\n".join(f"x_{i} = {i}" for i in range(60)), encoding="utf-8")

    cfg = RepoGuardConfig()
    cfg.code_quality.max_file_lines = 50
    ctx = ScanContext(repo_root=temp_repo, config=cfg)

    analyzer = CodeQualityAnalyzer()
    findings = analyzer.analyze(ctx)

    large_findings = [f for f in findings if f.id == "QUAL001"]
    assert len(large_findings) == 1
    assert "60 > 50" in large_findings[0].description
