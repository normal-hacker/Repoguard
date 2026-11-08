"""Tests for DependencyAnalyzer: unpinned dependencies, OSV API integration, and error resilience."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import requests

from repoguard.analyzers.dependencies import DependencyAnalyzer
from repoguard.config import RepoGuardConfig
from repoguard.core.context import ScanContext


def test_unpinned_dependencies(temp_repo: Path) -> None:
    req_file = temp_repo / "requirements.txt"
    req_file.write_text("requests\nflask>=2.0.0\nclick==8.1.3\n", encoding="utf-8")

    cfg = RepoGuardConfig()
    cfg.network.enabled = False  # Offline
    ctx = ScanContext(repo_root=temp_repo, config=cfg)

    analyzer = DependencyAnalyzer()
    findings = analyzer.analyze(ctx)

    unpinned = [f for f in findings if f.id == "DEP001"]
    unpinned_names = [f.description for f in unpinned]

    assert any("requests" in d for d in unpinned_names)
    assert any("flask" in d for d in unpinned_names)
    assert not any("click" in d for d in unpinned_names)  # click was pinned with ==


def test_osv_vulnerability_detection(temp_repo: Path, monkeypatch) -> None:
    req_file = temp_repo / "requirements.txt"
    req_file.write_text("vulnerable-pkg==1.0.0\n", encoding="utf-8")

    # Mock OSV API response
    def mock_post(url, json=None, timeout=None):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-1234-abcd",
                    "summary": "Remote code execution vulnerability",
                }
            ]
        }
        return mock_resp

    # Mock PyPI response (no update)
    def mock_get(url, timeout=None):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"info": {"version": "1.0.0"}}
        return mock_resp

    monkeypatch.setattr(requests, "post", mock_post)
    monkeypatch.setattr(requests, "get", mock_get)

    ctx = ScanContext(repo_root=temp_repo, network_enabled=True)
    analyzer = DependencyAnalyzer()
    findings = analyzer.analyze(ctx)

    vuln_findings = [f for f in findings if f.id == "DEP002"]
    assert len(vuln_findings) == 1
    assert "GHSA-1234-abcd" in vuln_findings[0].description
    assert vuln_findings[0].severity.value == "high"


def test_outdated_dependency_detection(temp_repo: Path, monkeypatch) -> None:
    req_file = temp_repo / "requirements.txt"
    req_file.write_text("safe-lib==1.0.0\n", encoding="utf-8")

    # Mock OSV (no vulns)
    def mock_post(url, json=None, timeout=None):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulns": []}
        return mock_resp

    # Mock PyPI (latest version is 2.0.0)
    def mock_get(url, timeout=None):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"info": {"version": "2.0.0"}}
        return mock_resp

    monkeypatch.setattr(requests, "post", mock_post)
    monkeypatch.setattr(requests, "get", mock_get)

    ctx = ScanContext(repo_root=temp_repo, network_enabled=True)
    analyzer = DependencyAnalyzer()
    findings = analyzer.analyze(ctx)

    outdated_findings = [f for f in findings if f.id == "DEP003"]
    assert len(outdated_findings) == 1
    assert "1.0.0 -> 2.0.0" in outdated_findings[0].description


def test_network_failure_resilience(temp_repo: Path, monkeypatch) -> None:
    req_file = temp_repo / "requirements.txt"
    req_file.write_text("requests==2.28.0\n", encoding="utf-8")

    # Network exceptions should not crash analysis
    def mock_error(*args, **kwargs):
        raise requests.ConnectionError("Network disconnected")

    monkeypatch.setattr(requests, "post", mock_error)
    monkeypatch.setattr(requests, "get", mock_error)

    ctx = ScanContext(repo_root=temp_repo, network_enabled=True)
    analyzer = DependencyAnalyzer()
    # Does not raise an error
    findings = analyzer.analyze(ctx)
    assert isinstance(findings, list)


def test_package_json_parsing(temp_repo: Path) -> None:
    pkg_json = temp_repo / "package.json"
    pkg_json.write_text(
        """{
        "dependencies": {
            "express": "^4.18.2",
            "lodash": "4.17.21"
        }
    }""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo, network_enabled=False)
    analyzer = DependencyAnalyzer()
    findings = analyzer.analyze(ctx)

    # express with ^ is unpinned
    unpinned = [f for f in findings if f.id == "DEP001"]
    assert any("express" in f.description for f in unpinned)
    assert not any("lodash" in f.description for f in unpinned)
