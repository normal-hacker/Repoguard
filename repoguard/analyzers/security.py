"""Security analyzer detecting exposed secrets, dangerous calls, and insecure configurations."""

from __future__ import annotations

import re
from typing import ClassVar, NamedTuple

from repoguard.core.context import ScanContext
from repoguard.core.findings import Category, Confidence, Finding, Severity
from repoguard.plugins.base import BaseAnalyzer


class SecretRule(NamedTuple):
    id: str
    name: str
    pattern: re.Pattern
    severity: Severity
    description: str


class SecurityAnalyzer(BaseAnalyzer):
    """Detects credentials, API keys, private keys, dangerous code patterns, and insecure configs."""

    name = "security"
    description = "Scans for hardcoded secrets, exposed keys, and insecure code patterns"
    category = Category.SECURITY
    version = "1.0.0"

    SECRET_RULES: ClassVar[list[SecretRule]] = [
        SecretRule(
            id="SEC001",
            name="AWS Access Key",
            pattern=re.compile(
                r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
            ),
            severity=Severity.CRITICAL,
            description="Exposed AWS Access Key ID detected.",
        ),
        SecretRule(
            id="SEC002",
            name="GitHub Token",
            pattern=re.compile(
                r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})"
            ),
            severity=Severity.CRITICAL,
            description="Exposed GitHub personal access or OAuth token detected.",
        ),
        SecretRule(
            id="SEC003",
            name="Slack Webhook / Token",
            pattern=re.compile(
                r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+|xox[baprs]-[0-9a-zA-Z]{10,48}"
            ),
            severity=Severity.HIGH,
            description="Exposed Slack webhook URL or bot token detected.",
        ),
        SecretRule(
            id="SEC004",
            name="Private Key",
            pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
            severity=Severity.CRITICAL,
            description="Exposed cryptographic private key detected in repository.",
        ),
        SecretRule(
            id="SEC005",
            name="Generic Hardcoded Secret",
            pattern=re.compile(
                r"(?i)(?:api_key|apikey|secret_key|auth_token|client_secret|password)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{16,})['\"]"
            ),
            severity=Severity.HIGH,
            description="Potentially hardcoded API key, token, or password assigned in source file.",
        ),
    ]

    DANGEROUS_PATTERNS: ClassVar[list[tuple[str, re.Pattern, Severity, str]]] = [
        (
            "SEC006",
            re.compile(r"shell\s*=\s*True"),
            Severity.HIGH,
            "Use of shell=True in subprocess call may lead to command injection.",
        ),
        (
            "SEC007",
            re.compile(r"(?<![a-zA-Z0-9_])eval\s*\("),
            Severity.HIGH,
            "Use of eval() function allows arbitrary code execution.",
        ),
    ]

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        scannable_exts = {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".json",
            ".yml",
            ".yaml",
            ".env",
            ".toml",
            ".ini",
            ".cfg",
            ".sh",
            ".bash",
            ".zsh",
            ".rb",
            ".go",
            ".java",
            ".php",
            ".txt",
            ".md",
            ".key",
            ".pem",
            ".crt",
        }

        for file_path in context.files:
            # Skip binary and very large files
            if file_path.suffix.lower() not in scannable_exts and not file_path.name.startswith(
                ".env"
            ):
                continue

            rel_path = context.get_relative_path(file_path)
            lines = context.read_file_lines(file_path)
            if lines is None:
                continue

            # 1. Check for exposed secrets line by line
            for line_idx, line in enumerate(lines, start=1):
                # Don't scan excessively long lines (e.g. minified bundles)
                if len(line) > 1000:
                    continue

                for rule in self.SECRET_RULES:
                    match = rule.pattern.search(line)
                    if match:
                        secret_val = match.group(0)
                        masked_evidence = self._mask_secret(secret_val)
                        findings.append(
                            Finding(
                                id=rule.id,
                                analyzer=self.name,
                                category=self.category,
                                severity=rule.severity,
                                description=f"{rule.description} ({rule.name})",
                                file_path=rel_path,
                                line_number=line_idx,
                                evidence=f"Found: {masked_evidence}",
                                remediation="Revoke this credential immediately and store secrets in environment variables or a secret vault.",
                                confidence=Confidence.HIGH,
                            )
                        )

                # 2. Check for dangerous code calls in code files
                if file_path.suffix.lower() in [".py", ".js", ".ts"]:
                    for pattern_id, pattern, severity, desc in self.DANGEROUS_PATTERNS:
                        if pattern.search(line):
                            findings.append(
                                Finding(
                                    id=pattern_id,
                                    analyzer=self.name,
                                    category=self.category,
                                    severity=severity,
                                    description=desc,
                                    file_path=rel_path,
                                    line_number=line_idx,
                                    evidence=line.strip()[:100],
                                    remediation="Refactor to avoid shell=True or eval(). Pass argument lists directly.",
                                    confidence=Confidence.MEDIUM,
                                )
                            )

            # 3. Check for exposed .env files committed to repository
            if file_path.name == ".env" or file_path.name.endswith(".env.local"):
                findings.append(
                    Finding(
                        id="SEC008",
                        analyzer=self.name,
                        category=self.category,
                        severity=Severity.HIGH,
                        description=f"Environment secret file '{rel_path}' is committed to repository.",
                        file_path=rel_path,
                        remediation="Add '.env' and '.env.*' to .gitignore and remove it from git tracking.",
                        confidence=Confidence.HIGH,
                    )
                )

        return findings

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """Never print complete secret values. Mask all but prefix and suffix."""
        if len(secret) <= 6:
            return "***"
        prefix = secret[:4]
        suffix = secret[-2:] if len(secret) > 10 else ""
        masked_length = len(secret) - len(prefix) - len(suffix)
        return f"{prefix}{'*' * min(masked_length, 12)}{suffix}"
