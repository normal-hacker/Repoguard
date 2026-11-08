"""Tests for SecurityAnalyzer: secret detection, secret masking, and dangerous calls."""

from __future__ import annotations

from pathlib import Path

from repoguard.analyzers.security import SecurityAnalyzer
from repoguard.core.context import ScanContext


def test_aws_key_detection_and_masking(temp_repo: Path) -> None:
    test_file = temp_repo / "aws_helper.py"
    # Real-shaped test AWS key ID
    test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    aws_findings = [f for f in findings if f.id == "SEC001"]
    assert len(aws_findings) == 1
    finding = aws_findings[0]
    assert finding.severity.value == "critical"
    # Verify complete secret is NOT in evidence
    assert "AKIAIOSFODNN7EXAMPLE" not in (finding.evidence or "")
    assert "AKIA" in (finding.evidence or "")
    assert "*" in (finding.evidence or "")


def test_github_token_detection(temp_repo: Path) -> None:
    test_file = temp_repo / "ci_script.sh"
    test_file.write_text(
        'export GITHUB_TOKEN="ghp_1234567890abcdef1234567890abcdef1234"\n', encoding="utf-8"
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    gh_findings = [f for f in findings if f.id == "SEC002"]
    assert len(gh_findings) == 1
    assert "ghp_1234567890abcdef1234567890abcdef1234" not in (gh_findings[0].evidence or "")


def test_private_key_detection(temp_repo: Path) -> None:
    key_file = temp_repo / "server.key"
    key_file.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    pk_findings = [f for f in findings if f.id == "SEC004"]
    assert len(pk_findings) == 1


def test_dangerous_shell_and_eval(temp_repo: Path) -> None:
    code_file = temp_repo / "utils.py"
    code_file.write_text(
        """import subprocess

def run_user_cmd(cmd):
    eval(cmd)
    subprocess.Popen(cmd, shell=True)
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    finding_ids = [f.id for f in findings]
    assert "SEC006" in finding_ids  # shell=True
    assert "SEC007" in finding_ids  # eval()


def test_env_file_detection(temp_repo: Path) -> None:
    env_file = temp_repo / ".env"
    env_file.write_text("DATABASE_URL=postgres://user:pass@localhost/db\n", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    env_findings = [f for f in findings if f.id == "SEC008"]
    assert len(env_findings) == 1
