"""Tests for example Docker analyzer plugin."""

from __future__ import annotations

from pathlib import Path

from repoguard_docker_analyzer.analyzer import DockerAnalyzer

from repoguard.core.context import ScanContext


def test_docker_analyzer_unpinned_and_root(temp_repo: Path) -> None:
    dockerfile = temp_repo / "Dockerfile"
    dockerfile.write_text(
        """FROM node:latest
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "server.js"]
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = DockerAnalyzer()
    findings = analyzer.analyze(ctx)

    finding_ids = [f.id for f in findings]
    assert "DOCK001" in finding_ids  # Unpinned :latest base image
    assert "DOCK002" in finding_ids  # Missing USER (root)


def test_docker_analyzer_secure_dockerfile(temp_repo: Path) -> None:
    dockerfile = temp_repo / "Dockerfile"
    dockerfile.write_text(
        """FROM python:3.11.8-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
USER appuser
CMD ["python", "main.py"]
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = DockerAnalyzer()
    findings = analyzer.analyze(ctx)

    assert len(findings) == 0


def test_docker_analyzer_insecure_remote_add(temp_repo: Path) -> None:
    dockerfile = temp_repo / "Dockerfile"
    dockerfile.write_text(
        """FROM alpine:3.19
ADD https://example.com/binary.tar.gz /usr/local/bin/
USER nonroot
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = DockerAnalyzer()
    findings = analyzer.analyze(ctx)

    finding_ids = [f.id for f in findings]
    assert "DOCK003" in finding_ids  # Insecure remote ADD
