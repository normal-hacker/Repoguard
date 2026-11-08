"""Regression and unit tests for SecurityAnalyzer:

- Distinguish real credentials from dummy test fixtures & placeholders
- AST-based dangerous code detection (eval, subprocess shell=True)
- Discarding comments, docstrings, and strings containing eval/shell=True
- Secret masking in evidence
- Duplicate finding prevention
"""

from __future__ import annotations

import base64
from pathlib import Path

from repoguard.analyzers.security import SecurityAnalyzer
from repoguard.core.context import ScanContext
from repoguard.core.findings import Finding, Severity

# ---------------------------------------------------------------------------
# 1. Real vs. Fake Secret Detection
# ---------------------------------------------------------------------------


def test_actual_exposed_credential_detection(temp_repo: Path) -> None:
    """Real-looking credentials (high entropy, no dummy words) MUST be detected and masked."""
    # Build tokens dynamically so test source itself does not match
    real_aws = "AKIA" + "2G4HJ8K9L0MN1P2Q"
    real_gh = "ghp_" + "v9Y2kP8mN5qL3rT1wX7zB4cD6fH8jK0mS2aU"

    test_file = temp_repo / "credentials.py"
    test_file.write_text(
        f'AWS_ACCESS_KEY = "{real_aws}"\nGITHUB_AUTH_TOKEN = "{real_gh}"\n',
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    aws_findings = [f for f in findings if f.id == "SEC001"]
    gh_findings = [f for f in findings if f.id == "SEC002"]

    assert len(aws_findings) == 1
    assert aws_findings[0].severity == Severity.CRITICAL
    # Secret MUST be masked in evidence
    assert real_aws not in (aws_findings[0].evidence or "")
    assert aws_findings[0].evidence.startswith("Found: AKIA")

    assert len(gh_findings) == 1
    assert gh_findings[0].severity == Severity.CRITICAL
    assert real_gh not in (gh_findings[0].evidence or "")
    assert gh_findings[0].evidence.startswith("Found: ghp_")


def test_fake_aws_credentials_ignored(temp_repo: Path) -> None:
    """Official documentation keys and dummy AWS placeholders must NOT be flagged."""
    test_file = temp_repo / "mock_aws.py"
    test_file.write_text(
        "# Official Amazon documentation example key\n"
        'EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'DUMMY_KEY = "AKIA0000000000000000"\n'
        'TEMPLATE_KEY = "AKIAEXAMPLEKEY12345"\n',
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    aws_findings = [f for f in findings if f.id == "SEC001"]
    assert len(aws_findings) == 0


def test_fake_github_tokens_ignored(temp_repo: Path) -> None:
    """Sequential or placeholder GitHub tokens must NOT be flagged as exposed secrets."""
    test_file = temp_repo / "mock_tokens.py"
    test_file.write_text(
        'FAKE_GH_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"\n'
        'DUMMY_GH_TOKEN = "ghp_dummytokenexampleplaceholder1234"\n',
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    gh_findings = [f for f in findings if f.id == "SEC002"]
    assert len(gh_findings) == 0


def test_private_key_test_fixtures_ignored(temp_repo: Path) -> None:
    """Private key fixtures containing ellipsis (...) or truncated stubs must NOT be flagged."""
    key_file = temp_repo / "server.key"
    key_file.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    pk_findings = [f for f in findings if f.id == "SEC004"]
    assert len(pk_findings) == 0


def test_actual_private_key_detected(temp_repo: Path) -> None:
    """A genuine, non-placeholder private key MUST be detected."""
    # Generate realistic Base64 payload (> 100 characters, no ellipsis)
    raw_bytes = bytes((i * 37) % 256 for i in range(150))
    encoded_body = base64.b64encode(raw_bytes).decode("ascii")

    key_file = temp_repo / "id_rsa"
    key_file.write_text(
        f"-----BEGIN RSA PRIVATE KEY-----\n{encoded_body}\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    pk_findings = [f for f in findings if f.id == "SEC004"]
    assert len(pk_findings) == 1
    assert pk_findings[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# 2. AST-Based Dangerous Code Detection
# ---------------------------------------------------------------------------


def test_eval_in_executable_code(temp_repo: Path) -> None:
    """Actual eval() and exec() AST function calls MUST be detected."""
    code_file = temp_repo / "calculator.py"
    code_file.write_text(
        """def compute(expr):
    return eval(expr)

def execute_user_script(script):
    exec(script)
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    eval_findings = [f for f in findings if f.id == "SEC007"]
    assert len(eval_findings) == 2
    assert any(f.line_number == 2 for f in eval_findings)
    assert any(f.line_number == 5 for f in eval_findings)


def test_eval_inside_strings_and_comments_ignored(temp_repo: Path) -> None:
    """Mentions of eval() in comments, docstrings, assertions, or string constants MUST be ignored."""
    code_file = temp_repo / "safe_eval_reference.py"
    code_file.write_text(
        '''# Rule: Never call eval() on untrusted user inputs!
"""
Documentation: This module does NOT use eval() or exec().
Use ast.literal_eval() instead.
"""
def check_code(output_text: str):
    # String literal mention
    rule_desc = "Use of eval() function allows arbitrary code execution."
    remediation = "Refactor to avoid eval()."
    assert "eval()" not in output_text
    return rule_desc
''',
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    eval_findings = [f for f in findings if f.id == "SEC007"]
    assert len(eval_findings) == 0


def test_subprocess_shell_true_detected(temp_repo: Path) -> None:
    """Actual subprocess calls passing shell=True keyword argument MUST be detected."""
    code_file = temp_repo / "runner.py"
    code_file.write_text(
        """import subprocess

def run_cmd(user_cmd):
    subprocess.Popen(user_cmd, shell=True)
    subprocess.run(["echo", "hi"], shell=True)
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    shell_findings = [f for f in findings if f.id == "SEC006"]
    assert len(shell_findings) == 2
    assert any(f.line_number == 4 for f in shell_findings)
    assert any(f.line_number == 5 for f in shell_findings)


def test_shell_true_inside_documentation_ignored(temp_repo: Path) -> None:
    """Mentions of shell=True in regexes, rule definitions, comments, and strings MUST be ignored."""
    code_file = temp_repo / "rule_definitions.py"
    code_file.write_text(
        """# Caution: shell=True should not be used
import re

SHELL_PATTERN = re.compile(r"shell\\s*=\\s*True")
DESCRIPTION = "Use of shell=True in subprocess call may lead to command injection."
REMEDIATION = "Refactor to avoid shell=True or eval()."

def log_warning():
    msg = "Detected shell=True in configuration"
    return msg
""",
        encoding="utf-8",
    )

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    shell_findings = [f for f in findings if f.id == "SEC006"]
    assert len(shell_findings) == 0


# ---------------------------------------------------------------------------
# 3. Environment Secrets & Duplicate Prevention
# ---------------------------------------------------------------------------


def test_env_file_detection(temp_repo: Path) -> None:
    """Committed .env files must be flagged under SEC008."""
    env_file = temp_repo / ".env"
    env_file.write_text("DATABASE_URL=postgres://user:pass@localhost/db\n", encoding="utf-8")

    ctx = ScanContext(repo_root=temp_repo)
    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(ctx)

    env_findings = [f for f in findings if f.id == "SEC008"]
    assert len(env_findings) == 1
    assert env_findings[0].severity == Severity.HIGH


def test_duplicate_finding_prevention(temp_repo: Path) -> None:
    """Ensure duplicate findings with identical fingerprints are deduplicated without merging separate issues."""
    from repoguard.core.scanner import RepoScanner

    # Create file with two separate genuine issues on line 4 and line 7
    code_file = temp_repo / "dual_eval.py"
    code_file.write_text(
        """# Line 1
# Line 2
def first_bad(x):
    eval(x)

def second_bad(y):
    eval(y)
""",
        encoding="utf-8",
    )

    scanner = RepoScanner(repo_root=temp_repo)
    result = scanner.run()

    eval_findings = [f for f in result.findings if f.id == "SEC007"]
    # Two distinct line numbers -> 2 distinct findings
    assert len(eval_findings) == 2
    assert {f.line_number for f in eval_findings} == {4, 7}

    # Verify fingerprint equality on duplicate finding objects
    f1 = eval_findings[0]
    duplicate_f1 = Finding(
        id=f1.id,
        analyzer=f1.analyzer,
        category=f1.category,
        severity=f1.severity,
        description=f1.description,
        file_path=f1.file_path,
        line_number=f1.line_number,
        remediation=f1.remediation,
    )
    assert f1.fingerprint == duplicate_f1.fingerprint
    assert len({f1, duplicate_f1}) == 1
