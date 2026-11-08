"""Testing analyzer detecting test suites, frameworks, CI test execution, and coverage health."""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from repoguard.core.context import ScanContext
from repoguard.core.findings import Category, Confidence, Finding, Severity
from repoguard.plugins.base import BaseAnalyzer


class TestingAnalyzer(BaseAnalyzer):
    """Analyzes test presence, test frameworks, CI test execution, and test file coverage."""

    __test__ = False  # Prevent Pytest from collecting this as a test class
    name = "testing"
    description = (
        "Detects test suites, frameworks, CI test automation, and test coverage indicators"
    )
    category = Category.TESTING
    version = "1.0.0"

    TEST_DIR_PATTERNS: ClassVar[list[str]] = [
        "tests",
        "test",
        "spec",
        "specs",
        "__tests__",
    ]

    TEST_FILE_PATTERNS: ClassVar[list[str]] = [
        "test_*.py",
        "*_test.py",
        "*.test.js",
        "*.spec.js",
        "*.test.ts",
        "*.spec.ts",
        "*.test.jsx",
        "*.spec.jsx",
        "*.test.tsx",
        "*.spec.tsx",
        "*_test.go",
    ]

    FRAMEWORK_CONFIGS: ClassVar[list[str]] = [
        "pytest.ini",
        "setup.cfg",
        "tox.ini",
        ".coveragerc",
        "jest.config.js",
        "jest.config.ts",
        "vitest.config.ts",
        "vitest.config.js",
    ]

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        test_files = self._find_test_files(context)
        frameworks = self._detect_frameworks(context)
        source_files = self._find_source_files(context)

        # 1. Check for absence of test files
        if not test_files:
            # Check if testing framework is configured despite missing test files
            if frameworks:
                findings.append(
                    Finding(
                        id="TEST003",
                        analyzer=self.name,
                        category=self.category,
                        severity=Severity.HIGH,
                        description=f"Testing framework configured ({', '.join(frameworks)}) but no test files were found.",
                        remediation="Write unit tests in a dedicated 'tests/' directory to exercise your code.",
                        confidence=Confidence.HIGH,
                        metadata={"frameworks": frameworks},
                    )
                )
            else:
                findings.append(
                    Finding(
                        id="TEST001",
                        analyzer=self.name,
                        category=self.category,
                        severity=Severity.HIGH,
                        description="No automated test files or test directories detected in repository.",
                        remediation="Set up a test framework (such as pytest) and create tests in a 'tests/' directory.",
                        confidence=Confidence.HIGH,
                    )
                )
            return findings

        # 2. Check test ratio when source files exist
        if len(source_files) > 15 and len(test_files) <= 1:
            findings.append(
                Finding(
                    id="TEST002",
                    analyzer=self.name,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Low test volume: found {len(test_files)} test file for {len(source_files)} source files."
                    ),
                    remediation="Expand automated test coverage across critical application modules.",
                    confidence=Confidence.MEDIUM,
                    metadata={
                        "test_files_count": len(test_files),
                        "source_files_count": len(source_files),
                    },
                )
            )

        # 3. Check CI test execution
        self._check_ci_test_execution(context, findings)

        return findings

    def _find_test_files(self, context: ScanContext) -> list[Path]:
        """Detect recognized test files in repository."""
        matched: set[Path] = set()

        for pattern in self.TEST_FILE_PATTERNS:
            for file_path in context.list_files(pattern=pattern):
                matched.add(file_path)

        for path in context.files:
            rel = context.get_relative_path(path)
            parts = rel.split("/")
            if any(part.lower() in self.TEST_DIR_PATTERNS for part in parts[:-1]):
                matched.add(path)

        return sorted(matched)

    def _find_source_files(self, context: ScanContext) -> list[Path]:
        """Identify non-test production source code files."""
        sources: list[Path] = []
        source_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".c", ".cpp"}
        test_files = set(self._find_test_files(context))

        for file_path in context.files:
            if file_path.suffix.lower() in source_exts and file_path not in test_files:
                sources.append(file_path)

        return sources

    def _detect_frameworks(self, context: ScanContext) -> list[str]:
        """Detect configured test frameworks."""
        detected: set[str] = set()

        for conf in self.FRAMEWORK_CONFIGS:
            if context.has_file(conf):
                if "pytest" in conf:
                    detected.add("pytest")
                elif "jest" in conf:
                    detected.add("jest")
                elif "vitest" in conf:
                    detected.add("vitest")
                elif "tox" in conf:
                    detected.add("tox")

        # Check pyproject.toml
        pyproject_content = context.read_file("pyproject.toml")
        if pyproject_content and (
            "tool.pytest" in pyproject_content or "pytest" in pyproject_content
        ):
            detected.add("pytest")

        # Check package.json
        pkg_content = context.read_file("package.json")
        if pkg_content:
            for fw in ["jest", "mocha", "vitest", "ava", "jasmine"]:
                if fw in pkg_content:
                    detected.add(fw)

        return sorted(detected)

    def _check_ci_test_execution(self, context: ScanContext, findings: list[Finding]) -> None:
        """Inspect GitHub Actions workflows to see if automated tests are executed in CI."""
        workflow_files = [
            f
            for f in context.files
            if context.get_relative_path(f).startswith(".github/workflows/")
            and f.suffix in [".yml", ".yaml"]
        ]

        if not workflow_files:
            # Missing CI is also evaluated by cicd analyzer, but note here for testing
            return

        has_test_step = False
        test_patterns = [
            r"\bpytest\b",
            r"\bnpm\s+test\b",
            r"\byarn\s+test\b",
            r"\bpnpm\s+test\b",
            r"\bgo\s+test\b",
            r"\bcargo\s+test\b",
            r"\bpython\s+-m\s+unittest\b",
            r"\btox\b",
        ]

        for wf in workflow_files:
            content = context.read_file(wf)
            if not content:
                continue
            for pattern in test_patterns:
                if re.search(pattern, content):
                    has_test_step = True
                    break
            if has_test_step:
                break

        if not has_test_step:
            findings.append(
                Finding(
                    id="TEST004",
                    analyzer=self.name,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    description="CI workflows (.github/workflows) do not appear to execute automated tests.",
                    remediation="Add a workflow step running automated tests (e.g., `pytest` or `npm test`) on pull requests.",
                    confidence=Confidence.MEDIUM,
                )
            )
