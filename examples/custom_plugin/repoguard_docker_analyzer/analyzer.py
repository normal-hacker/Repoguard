"""Docker container analyzer plugin for RepoGuard."""

from __future__ import annotations

from repoguard.core.context import ScanContext
from repoguard.core.findings import Category, Confidence, Finding, Severity
from repoguard.plugins.base import BaseAnalyzer


class DockerAnalyzer(BaseAnalyzer):
    """Analyzes Dockerfiles and Containerfiles for container security antipatterns."""

    name = "docker"
    description = "Inspects Dockerfiles for unpinned base images, root user execution, and insecure instructions"
    category = Category.CUSTOM
    version = "0.1.0"

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        dockerfiles = [
            f
            for f in context.files
            if f.name.lower() in ["dockerfile", "containerfile"]
            or f.name.lower().startswith("dockerfile.")
        ]

        for df in dockerfiles:
            rel_path = context.get_relative_path(df)
            lines = context.read_file_lines(df)
            if not lines:
                continue

            has_user_instruction = False

            for idx, line in enumerate(lines, start=1):
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue

                # 1. Unpinned or :latest base image tag
                if clean.upper().startswith("FROM "):
                    parts = clean.split()
                    if len(parts) >= 2:
                        image = parts[1]
                        if ":latest" in image or ":" not in image:
                            findings.append(
                                Finding(
                                    id="DOCK001",
                                    analyzer=self.name,
                                    category=self.category,
                                    severity=Severity.MEDIUM,
                                    description=f"Base image '{image}' uses unpinned or :latest tag in {rel_path}",
                                    file_path=rel_path,
                                    line_number=idx,
                                    evidence=clean,
                                    remediation="Pin base images to an exact digest SHA or specific immutable release tag.",
                                    confidence=Confidence.HIGH,
                                )
                            )

                # Check for USER instruction
                if clean.upper().startswith("USER "):
                    has_user_instruction = True

                # 2. Insecure ADD instruction for remote artifacts
                if clean.upper().startswith("ADD ") and ("http://" in clean or "https://" in clean):
                    findings.append(
                        Finding(
                            id="DOCK003",
                            analyzer=self.name,
                            category=self.category,
                            severity=Severity.LOW,
                            description=f"Insecure ADD instruction with remote URL in {rel_path}",
                            file_path=rel_path,
                            line_number=idx,
                            evidence=clean,
                            remediation="Use 'curl' or 'wget' inside a RUN layer or COPY local verified artifacts.",
                            confidence=Confidence.MEDIUM,
                        )
                    )

            # 3. Missing non-root USER instruction
            if not has_user_instruction:
                findings.append(
                    Finding(
                        id="DOCK002",
                        analyzer=self.name,
                        category=self.category,
                        severity=Severity.HIGH,
                        description=f"Dockerfile '{rel_path}' does not specify a non-root USER instruction.",
                        file_path=rel_path,
                        remediation="Add 'USER <non-root-user>' to avoid running container processes with root privileges.",
                        confidence=Confidence.HIGH,
                    )
                )

        return findings
