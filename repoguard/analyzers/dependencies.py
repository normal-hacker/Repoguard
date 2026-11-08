"""Dependency analyzer checking pinned versions, outdated packages, and OSV vulnerabilities."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import requests

from repoguard.core.context import ScanContext
from repoguard.core.findings import Category, Confidence, Finding, Severity
from repoguard.plugins.base import BaseAnalyzer

OSV_API_URL = "https://api.osv.dev/v1/query"
PYPI_API_URL = "https://pypi.org/pypi/{package}/json"
NPM_REGISTRY_URL = "https://registry.npmjs.org/{package}"


@dataclass
class ParsedDependency:
    name: str
    specifier: str
    pinned_version: str | None
    ecosystem: str  # "PyPI" or "npm"
    file_path: str
    line_number: int | None = None


class DependencyAnalyzer(BaseAnalyzer):
    """Analyzes repository dependencies for security vulnerabilities and update status."""

    name = "dependencies"
    description = "Inspects dependencies for unpinned versions, outdated releases, and CVEs via OSV"
    category = Category.DEPENDENCIES
    version = "1.0.0"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._vuln_cache: dict[str, list[dict[str, Any]]] = {}
        self._latest_version_cache: dict[str, str | None] = {}

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        dependencies = self._discover_dependencies(context)

        if not dependencies and not self._has_manifests(context):
            # No dependencies found and no manifests
            return findings

        for dep in dependencies:
            # 1. Check for unpinned dependencies
            if not dep.pinned_version:
                findings.append(
                    Finding(
                        id="DEP001",
                        analyzer=self.name,
                        category=self.category,
                        severity=Severity.LOW,
                        description=f"Dependency '{dep.name}' is unpinned in {dep.file_path}",
                        file_path=dep.file_path,
                        line_number=dep.line_number,
                        evidence=f"Specification: {dep.name}{dep.specifier}",
                        remediation=f"Pin '{dep.name}' to a tested, exact version (e.g. {dep.name}==x.y.z)",
                        confidence=Confidence.HIGH,
                    )
                )

            # 2. Check network-dependent lookups if enabled
            if context.network_enabled and dep.pinned_version:
                timeout = context.config.network.timeout_seconds

                # A. Known vulnerabilities via OSV API
                vulns = self._check_osv_vulnerabilities(dep, timeout=timeout)
                for vuln in vulns:
                    vuln_id = vuln.get("id", "UNKNOWN-VULN")
                    summary = (
                        vuln.get("summary") or vuln.get("details") or "Known security vulnerability"
                    )
                    # Truncate summary for neatness
                    short_summary = (summary[:150] + "...") if len(summary) > 150 else summary

                    findings.append(
                        Finding(
                            id="DEP002",
                            analyzer=self.name,
                            category=self.category,
                            severity=Severity.HIGH,
                            description=f"Vulnerability {vuln_id} detected in {dep.name}@{dep.pinned_version}: {short_summary}",
                            file_path=dep.file_path,
                            line_number=dep.line_number,
                            evidence=f"Package: {dep.name}=={dep.pinned_version} (Advisory: {vuln_id})",
                            remediation=f"Upgrade '{dep.name}' to a patched version resolving advisory {vuln_id}",
                            confidence=Confidence.HIGH,
                            metadata={"advisory_id": vuln_id, "ecosystem": dep.ecosystem},
                        )
                    )

                # B. Outdated dependency check via package registries
                latest = self._fetch_latest_version(dep, timeout=timeout)
                if latest and latest != dep.pinned_version:
                    findings.append(
                        Finding(
                            id="DEP003",
                            analyzer=self.name,
                            category=self.category,
                            severity=Severity.LOW,
                            description=f"Dependency '{dep.name}' is outdated ({dep.pinned_version} -> {latest})",
                            file_path=dep.file_path,
                            line_number=dep.line_number,
                            evidence=f"Current: {dep.pinned_version}, Latest: {latest}",
                            remediation=f"Consider testing and updating '{dep.name}' to release {latest}",
                            confidence=Confidence.MEDIUM,
                            metadata={"latest_version": latest},
                        )
                    )

        return findings

    def _has_manifests(self, context: ScanContext) -> bool:
        return any(
            context.has_file(f)
            for f in ["requirements.txt", "pyproject.toml", "Pipfile", "package.json"]
        )

    def _discover_dependencies(self, context: ScanContext) -> list[ParsedDependency]:
        """Parse dependencies from requirements.txt, pyproject.toml, and package.json."""
        deps: list[ParsedDependency] = []

        # Python: requirements.txt
        for req_file in context.find_files_by_name(["requirements.txt", "requirements-dev.txt"]):
            rel_path = context.get_relative_path(req_file)
            lines = context.read_file_lines(req_file) or []
            for idx, line in enumerate(lines, start=1):
                clean = line.strip()
                if not clean or clean.startswith(("#", "-", "--")):
                    continue
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!]+.*)?$", clean)
                if match:
                    name = match.group(1).lower()
                    spec = match.group(2) or ""
                    pinned = None
                    pin_match = re.search(r"==\s*([0-9a-zA-Z\.\-]+)", spec)
                    if pin_match:
                        pinned = pin_match.group(1)
                    deps.append(
                        ParsedDependency(
                            name=name,
                            specifier=spec,
                            pinned_version=pinned,
                            ecosystem="PyPI",
                            file_path=rel_path,
                            line_number=idx,
                        )
                    )

        # Python: pyproject.toml
        pyproject_files = context.find_files_by_name(["pyproject.toml"])
        for pyproject in pyproject_files:
            rel_path = context.get_relative_path(pyproject)
            content = context.read_file(pyproject)
            if content:
                try:
                    import tomllib

                    data = tomllib.loads(content)
                    raw_deps = data.get("project", {}).get("dependencies", [])
                    for item in raw_deps:
                        if isinstance(item, str):
                            match = re.match(
                                r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!]+.*)?$", item.strip()
                            )
                            if match:
                                name = match.group(1).lower()
                                spec = match.group(2) or ""
                                pinned = None
                                pin_match = re.search(r"==\s*([0-9a-zA-Z\.\-]+)", spec)
                                if pin_match:
                                    pinned = pin_match.group(1)
                                deps.append(
                                    ParsedDependency(
                                        name=name,
                                        specifier=spec,
                                        pinned_version=pinned,
                                        ecosystem="PyPI",
                                        file_path=rel_path,
                                    )
                                )
                except Exception:
                    pass

        # JavaScript/Node: package.json
        pkg_json_files = context.find_files_by_name(["package.json"])
        for pkg_file in pkg_json_files:
            rel_path = context.get_relative_path(pkg_file)
            content = context.read_file(pkg_file)
            if content:
                try:
                    data = json.loads(content)
                    all_deps: dict[str, str] = {}
                    all_deps.update(data.get("dependencies", {}))
                    all_deps.update(data.get("devDependencies", {}))

                    for name, spec in all_deps.items():
                        clean_spec = str(spec).strip()
                        # Strict pin e.g. "1.2.3" without ^ or ~
                        pinned = None
                        if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+[0-9a-zA-Z\.\-]*$", clean_spec):
                            pinned = clean_spec
                        deps.append(
                            ParsedDependency(
                                name=name,
                                specifier=clean_spec,
                                pinned_version=pinned,
                                ecosystem="npm",
                                file_path=rel_path,
                            )
                        )
                except Exception:
                    pass

        return deps

    def _check_osv_vulnerabilities(
        self,
        dep: ParsedDependency,
        timeout: float = 10.0,
    ) -> list[dict[str, Any]]:
        """Query the open-source OSV vulnerability database for known CVEs/GHSAs."""
        if not dep.pinned_version:
            return []

        cache_key = f"{dep.ecosystem}:{dep.name}:{dep.pinned_version}"
        if cache_key in self._vuln_cache:
            return self._vuln_cache[cache_key]

        payload = {
            "package": {"name": dep.name, "ecosystem": dep.ecosystem},
            "version": dep.pinned_version,
        }

        try:
            resp = requests.post(OSV_API_URL, json=payload, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulns", [])
                self._vuln_cache[cache_key] = vulns
                return vulns
        except requests.RequestException:
            # Network failure or API unavailable handled gracefully
            pass

        self._vuln_cache[cache_key] = []
        return []

    def _fetch_latest_version(
        self,
        dep: ParsedDependency,
        timeout: float = 10.0,
    ) -> str | None:
        """Fetch latest version from PyPI or npm registry."""
        cache_key = f"{dep.ecosystem}:{dep.name}"
        if cache_key in self._latest_version_cache:
            return self._latest_version_cache[cache_key]

        try:
            if dep.ecosystem == "PyPI":
                url = PYPI_API_URL.format(package=dep.name)
                resp = requests.get(url, timeout=timeout)
                if resp.status_code == 200:
                    latest = resp.json().get("info", {}).get("version")
                    self._latest_version_cache[cache_key] = latest
                    return latest
            elif dep.ecosystem == "npm":
                url = NPM_REGISTRY_URL.format(package=dep.name)
                resp = requests.get(url, timeout=timeout)
                if resp.status_code == 200:
                    latest = resp.json().get("dist-tags", {}).get("latest")
                    self._latest_version_cache[cache_key] = latest
                    return latest
        except requests.RequestException:
            pass

        self._latest_version_cache[cache_key] = None
        return None
