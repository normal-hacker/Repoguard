"""Documentation analyzer checking repository documentation completeness and health."""

from __future__ import annotations

import re
from typing import ClassVar

from repoguard.core.context import ScanContext
from repoguard.core.findings import Category, Confidence, Finding, Severity
from repoguard.plugins.base import BaseAnalyzer


class DocumentationAnalyzer(BaseAnalyzer):
    """Analyzes repository documentation: README, installation, usage, license, and contribution guides."""

    name = "documentation"
    description = "Checks repository documentation completeness and health"
    category = Category.DOCUMENTATION
    version = "1.0.0"

    README_NAMES: ClassVar[list[str]] = [
        "readme.md",
        "readme.rst",
        "readme.txt",
        "readme",
    ]
    LICENSE_NAMES: ClassVar[list[str]] = [
        "license",
        "license.md",
        "license.txt",
        "copying",
        "copying.md",
        "copying.txt",
    ]
    CONTRIBUTING_NAMES: ClassVar[list[str]] = [
        "contributing.md",
        "contributing.rst",
        "contributing.txt",
        ".github/contributing.md",
        "docs/contributing.md",
    ]
    CONDUCT_NAMES: ClassVar[list[str]] = [
        "code_of_conduct.md",
        "code_of_conduct.txt",
        ".github/code_of_conduct.md",
    ]

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Check README presence
        readme_files = context.find_files_by_name(self.README_NAMES)
        if not readme_files:
            findings.append(
                Finding(
                    id="DOC001",
                    analyzer=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    description="Repository lacks a README file.",
                    file_path=None,
                    remediation="Add a comprehensive README.md explaining the project purpose, setup, and usage.",
                    confidence=Confidence.HIGH,
                )
            )
            # If no README exists, also check for license file
            self._check_license_file(context, findings)
            self._check_contributing_file(context, findings, in_readme=False)
            return findings

        primary_readme = readme_files[0]
        rel_readme = context.get_relative_path(primary_readme)
        content = context.read_file(primary_readme)

        if not content or len(content.strip()) < 50:
            findings.append(
                Finding(
                    id="DOC002",
                    analyzer=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    description="README file is empty or contains inadequate content (< 50 characters).",
                    file_path=rel_readme,
                    remediation="Expand the README with project overview, installation, and usage instructions.",
                    confidence=Confidence.HIGH,
                )
            )
        else:
            self._inspect_readme_sections(content, rel_readme, findings)

        # 2. Check License
        self._check_license_file(context, findings, readme_content=content, readme_path=rel_readme)

        # 3. Check Contribution guidelines
        self._check_contributing_file(
            context,
            findings,
            in_readme=self._has_section(content or "", ["contributing", "contribution"]),
        )

        return findings

    def _inspect_readme_sections(
        self,
        content: str,
        rel_readme: str,
        findings: list[Finding],
    ) -> None:
        """Inspect README sections for standard open-source documentation components."""
        # Installation instructions
        if not self._has_section(content, ["installation", "install", "getting started", "setup"]):
            findings.append(
                Finding(
                    id="DOC003",
                    analyzer=self.name,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    description="README lacks installation or setup instructions.",
                    file_path=rel_readme,
                    remediation="Add an 'Installation' or 'Getting Started' section with step-by-step setup commands.",
                    confidence=Confidence.MEDIUM,
                )
            )

        # Usage instructions
        if not self._has_section(
            content, ["usage", "quick start", "examples", "example", "how to use"]
        ):
            findings.append(
                Finding(
                    id="DOC004",
                    analyzer=self.name,
                    category=self.category,
                    severity=Severity.LOW,
                    description="README lacks usage instructions or examples.",
                    file_path=rel_readme,
                    remediation="Add a 'Usage' or 'Quick Start' section showing code snippets or command examples.",
                    confidence=Confidence.MEDIUM,
                )
            )

    def _has_section(self, content: str, keywords: list[str]) -> bool:
        """Check if Markdown or plain text contains headers with keywords."""
        lower_content = content.lower()
        for kw in keywords:
            # Matches `# Heading`, `## Heading`, `**Heading**`, etc.
            pattern = rf"(?:^|\n)\s*(?:#+\s*|[*_]{{2}})?\s*{re.escape(kw)}\b"
            if re.search(pattern, lower_content):
                return True
        return False

    def _check_license_file(
        self,
        context: ScanContext,
        findings: list[Finding],
        readme_content: str | None = None,
        readme_path: str | None = None,
    ) -> None:
        """Verify presence of LICENSE file or license declaration."""
        license_files = context.find_files_by_name(self.LICENSE_NAMES)
        if license_files:
            return

        has_readme_license = readme_content and self._has_section(
            readme_content, ["license", "licence"]
        )

        if not has_readme_license:
            findings.append(
                Finding(
                    id="DOC005",
                    analyzer=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    description="No LICENSE file or license declaration found in repository.",
                    file_path=readme_path,
                    remediation="Add an OSI-approved LICENSE file (e.g., MIT, Apache 2.0) to clarify rights and usage terms.",
                    confidence=Confidence.HIGH,
                )
            )

    def _check_contributing_file(
        self,
        context: ScanContext,
        findings: list[Finding],
        in_readme: bool = False,
    ) -> None:
        """Verify presence of CONTRIBUTING guide."""
        if in_readme:
            return

        for name in self.CONTRIBUTING_NAMES:
            if context.has_file(name):
                return

        findings.append(
            Finding(
                id="DOC006",
                analyzer=self.name,
                category=self.category,
                severity=Severity.LOW,
                description="Repository lacks dedicated contribution guidelines (CONTRIBUTING.md).",
                remediation="Add a CONTRIBUTING.md file guiding community contributors on development and pull requests.",
                confidence=Confidence.MEDIUM,
            )
        )
