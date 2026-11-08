"""CI/CD analyzer inspecting GitHub workflows, triggers, permissions, and action pinning."""

from __future__ import annotations

import re
from typing import Any

import yaml

from repoguard.core.context import ScanContext
from repoguard.core.findings import Category, Confidence, Finding, Severity
from repoguard.plugins.base import BaseAnalyzer


class CiCdAnalyzer(BaseAnalyzer):
    """Analyzes GitHub Actions workflows for best practices, permissions, and security."""

    name = "cicd"
    description = "Inspects GitHub Actions workflows for permissions, branch pinning, and CI health"
    category = Category.CICD
    version = "1.0.0"

    MUTABLE_BRANCHES = {"main", "master", "dev", "develop", "latest"}

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        workflow_files = [
            f
            for f in context.files
            if context.get_relative_path(f).startswith(".github/workflows/")
            and f.suffix in [".yml", ".yaml"]
        ]

        # 1. Detect missing workflows
        if not workflow_files:
            findings.append(
                Finding(
                    id="CICD001",
                    analyzer=self.name,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    description="No GitHub Actions workflows found in .github/workflows/.",
                    remediation="Add a CI workflow to automatically build, test, and validate code changes.",
                    confidence=Confidence.HIGH,
                )
            )
            return findings

        # 2. Inspect each workflow file
        for wf_file in workflow_files:
            rel_path = context.get_relative_path(wf_file)
            content = context.read_file(wf_file)
            if not content:
                continue

            # Parse YAML safely
            try:
                data = yaml.safe_load(content) or {}
            except yaml.YAMLError as exc:
                findings.append(
                    Finding(
                        id="CICD005",
                        analyzer=self.name,
                        category=self.category,
                        severity=Severity.HIGH,
                        description=f"Malformed YAML in workflow '{rel_path}': {exc}",
                        file_path=rel_path,
                        remediation="Fix YAML syntax error in workflow file.",
                        confidence=Confidence.HIGH,
                    )
                )
                continue

            self._check_workflow_permissions(data, rel_path, findings)
            self._check_action_pinning(content, rel_path, findings)

        return findings

    def _check_workflow_permissions(
        self,
        data: dict[str, Any],
        rel_path: str,
        findings: list[Finding],
    ) -> None:
        """Inspect workflow permissions for principle of least privilege."""
        permissions = data.get("permissions")

        if permissions == "write-all":
            findings.append(
                Finding(
                    id="CICD002",
                    analyzer=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    description="Workflow configures 'permissions: write-all', granting broad write access to GITHUB_TOKEN.",
                    file_path=rel_path,
                    remediation="Define fine-grained, read-only default permissions (e.g. `permissions: contents: read`).",
                    confidence=Confidence.HIGH,
                )
            )
        elif permissions is None:
            # Check if jobs define permissions
            jobs = data.get("jobs", {})
            has_job_permissions = any(
                "permissions" in job for job in jobs.values() if isinstance(job, dict)
            )
            if not has_job_permissions:
                findings.append(
                    Finding(
                        id="CICD003",
                        analyzer=self.name,
                        category=self.category,
                        severity=Severity.LOW,
                        description="Workflow lacks explicit least-privilege 'permissions' configuration.",
                        file_path=rel_path,
                        remediation="Explicitly specify top-level 'permissions: contents: read' to follow the principle of least privilege.",
                        confidence=Confidence.MEDIUM,
                    )
                )

    def _check_action_pinning(
        self,
        content: str,
        rel_path: str,
        findings: list[Finding],
    ) -> None:
        """Inspect action references for mutable branch tags."""
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            match = re.search(r"uses:\s*([a-zA-Z0-9_\-\./]+)@([a-zA-Z0-9_\-\.]+)", line)
            if match:
                action_name = match.group(1)
                ref = match.group(2)

                # Skip local actions (./) or docker actions
                if action_name.startswith((".", "docker://")):
                    continue

                if ref.lower() in self.MUTABLE_BRANCHES:
                    findings.append(
                        Finding(
                            id="CICD004",
                            analyzer=self.name,
                            category=self.category,
                            severity=Severity.MEDIUM,
                            description=f"Action '{action_name}' is pinned to mutable branch '@{ref}'.",
                            file_path=rel_path,
                            line_number=idx,
                            evidence=line.strip(),
                            remediation="Pin third-party GitHub Actions to a full commit SHA or tagged release (e.g. @v4.0.0).",
                            confidence=Confidence.HIGH,
                        )
                    )
