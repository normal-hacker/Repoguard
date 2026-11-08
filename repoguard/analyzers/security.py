"""Security analyzer detecting exposed secrets, dangerous calls, and insecure configurations."""

from __future__ import annotations

import ast
import re
from typing import ClassVar, NamedTuple

from repoguard.core.context import ScanContext
from repoguard.core.findings import Category, Confidence, Finding, Severity
from repoguard.plugins.base import BaseAnalyzer

COMMON_PLACEHOLDER_WORDS: set[str] = {
    "example",
    "sample",
    "dummy",
    "mock",
    "fake",
    "placeholder",
    "template",
    "replace_me",
    "replace_with_your",
    "change_me",
    "your_key",
    "your-key",
    "your_token",
    "insert_key",
    "not_a_secret",
    "test_key",
    "test_token",
    "test_secret",
    "dummy_key",
    "fake_token",
}


def _has_low_entropy_or_sequence(text: str) -> bool:
    """Check if string contains repetitive or sequential dummy character patterns."""
    lower = text.lower()
    # 4+ identical repeated characters in a row: e.g. '0000', 'xxxx', 'aaaa', '1111'
    if re.search(r"(.)\1{3,}", lower):
        return True

    # Sequential character patterns
    sequences = [
        "12345678",
        "01234567",
        "abcdefgh",
        "1234567890abcdef",
        "qwertyuiop",
        "asdfghjkl",
    ]
    return any(seq in lower for seq in sequences)


def _extract_private_key_body(content: str) -> str | None:
    """Extract Base64 body between BEGIN and END tags of a private key."""
    match = re.search(
        r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----(.*?)-----END (?:[A-Z ]+)?PRIVATE KEY-----",
        content,
        re.DOTALL,
    )
    if not match:
        return None
    raw_body = match.group(1)
    # Remove whitespace and newlines
    return re.sub(r"\s+", "", raw_body)


def is_placeholder_secret(
    rule_id: str,
    secret_text: str,
    line: str = "",
    full_content: str = "",
) -> bool:
    """Determine whether a matched secret is a harmless documentation or test placeholder.

    Preserves detection of real-looking secrets even in test files.
    """
    lower_secret = secret_text.lower()
    lower_line = line.lower()

    # 1. Assertions verifying that a secret was masked (e.g. 'assert secret not in evidence')
    if "assert " in lower_line and (" not in " in lower_line or "not in" in lower_line):
        return True

    # 2. Rule-specific handling for Private Keys (SEC004)
    # The header "-----BEGIN ... PRIVATE KEY-----" contains repeated dashes, so we must
    # evaluate the full key content rather than running generic secret_text heuristics.
    if rule_id == "SEC004":
        if "..." in secret_text or "..." in line:
            return True
        key_body = _extract_private_key_body(full_content if full_content else line)
        if key_body is not None:
            # Real RSA key is minimum 512 bits (~600 chars); EC is ~200 chars.
            if len(key_body) < 64 or "..." in key_body:
                return True
            return any(w in key_body.lower() for w in ("dummy", "example", "placeholder"))
        return "..." in line

    # 3. Variable explicitly named dummy/fake/mock/sample
    is_dummy_var = any(
        kw in lower_line
        for kw in (
            "dummy_",
            "fake_",
            "mock_",
            "sample_",
            "placeholder_",
            "example_",
        )
    )
    if is_dummy_var and (
        any(w in lower_secret for w in COMMON_PLACEHOLDER_WORDS)
        or _has_low_entropy_or_sequence(secret_text)
    ):
        return True

    # 4. Known placeholder words directly in the secret string
    if any(word in lower_secret for word in COMMON_PLACEHOLDER_WORDS):
        return True

    # 5. Low-entropy or sequential dummy patterns
    if _has_low_entropy_or_sequence(secret_text):
        return True

    # 6. Additional rule-specific entropy checks
    if rule_id == "SEC001":  # AWS Access Key (20 chars)
        if len(set(secret_text)) < 7:
            return True

    elif rule_id == "SEC002":  # GitHub token (ghp_ + 36 chars)
        token_body = secret_text[4:] if secret_text.startswith("ghp_") else secret_text
        if len(set(token_body.lower())) < 10:
            return True

    elif rule_id == "SEC003" and (
        "t00000000" in lower_secret or "b00000000" in lower_secret or "xxxx" in lower_secret
    ):
        return True

    return False


class DangerousPythonCallVisitor(ast.NodeVisitor):
    """AST visitor detecting genuine executable eval/exec calls and subprocess shell=True."""

    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # 1. Detect actual eval() / exec() executable calls
        if func_name in ("eval", "exec"):
            # Exclude ast.literal_eval which is safe
            is_literal_eval = (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "ast"
                and func_name == "literal_eval"
            )

            if not is_literal_eval:
                self.findings.append(
                    Finding(
                        id="SEC007",
                        analyzer="security",
                        category=Category.SECURITY,
                        severity=Severity.HIGH,
                        description=f"Use of {func_name}() function allows arbitrary code execution.",
                        file_path=self.rel_path,
                        line_number=node.lineno,
                        evidence=f"{func_name}(...)",
                        remediation=f"Avoid using {func_name}(). Use safer alternatives like ast.literal_eval() or explicit parsers.",
                        confidence=Confidence.HIGH,
                    )
                )

        # 2. Detect subprocess calls with shell=True
        has_shell_true = False
        for kw in node.keywords:
            if kw.arg == "shell" and (
                (isinstance(kw.value, ast.Constant) and kw.value.value is True)
                or (isinstance(kw.value, ast.Name) and kw.value.id == "True")
            ):
                has_shell_true = True
                break

        if has_shell_true:
            call_label = "subprocess call"
            if isinstance(node.func, ast.Attribute):
                call_label = f"{node.func.attr}(..., shell=True)"
            elif isinstance(node.func, ast.Name):
                call_label = f"{node.func.id}(..., shell=True)"

            self.findings.append(
                Finding(
                    id="SEC006",
                    analyzer="security",
                    category=Category.SECURITY,
                    severity=Severity.HIGH,
                    description="Use of shell=True in subprocess call may lead to command injection.",
                    file_path=self.rel_path,
                    line_number=node.lineno,
                    evidence=call_label,
                    remediation="Set shell=False and pass arguments as a list of strings to avoid shell injection.",
                    confidence=Confidence.HIGH,
                )
            )

        self.generic_visit(node)


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
            # Skip non-scannable files
            is_scannable = (
                file_path.suffix.lower() in scannable_exts
                or file_path.name.startswith(".env")
                or file_path.name.startswith("id_")
                or file_path.name.lower() in ("dockerfile", "jenkinsfile", "vagrantfile")
            )
            if not is_scannable:
                continue

            rel_path = context.get_relative_path(file_path)
            content = context.read_file(file_path)
            if content is None:
                continue

            lines = content.splitlines()

            # 1. Check for exposed secrets line by line
            for line_idx, line in enumerate(lines, start=1):
                # Don't scan excessively long lines (e.g. minified bundles)
                if len(line) > 1000:
                    continue

                for rule in self.SECRET_RULES:
                    match = rule.pattern.search(line)
                    if match:
                        matched_text = match.group(1) if match.lastindex else match.group(0)

                        # Filter out harmless dummy/placeholder values
                        if is_placeholder_secret(
                            rule.id, matched_text, line=line, full_content=content
                        ):
                            continue

                        masked_evidence = self._mask_secret(matched_text)
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

            # 2. Check for dangerous executable calls
            if file_path.suffix.lower() == ".py":
                # Use AST analysis for Python files
                try:
                    tree = ast.parse(content, filename=rel_path)
                    visitor = DangerousPythonCallVisitor(rel_path=rel_path)
                    visitor.visit(tree)
                    findings.extend(visitor.findings)
                except SyntaxError:
                    # If AST parsing fails, fallback safely
                    self._check_dangerous_lines(lines, rel_path, findings)
            elif file_path.suffix.lower() in [".js", ".ts", ".jsx", ".tsx"]:
                self._check_dangerous_lines(lines, rel_path, findings)

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

    def _check_dangerous_lines(
        self,
        lines: list[str],
        rel_path: str,
        findings: list[Finding],
    ) -> None:
        """Inspect non-Python code files for dangerous calls, ignoring comments and string literals."""
        eval_pattern = re.compile(r"(?<![a-zA-Z0-9_\.])eval\s*\(")
        shell_pattern = re.compile(r"shell\s*:\s*true", re.IGNORECASE)

        for line_idx, line in enumerate(lines, start=1):
            clean = line.strip()
            # Ignore comments
            if clean.startswith(("//", "/*", "*", "#")):
                continue

            # Ignore string literal lines (such as documentation, descriptions, or remediation messages)
            if clean.startswith(('"', "'", "`", "description", "remediation", "evidence")):
                continue

            if eval_pattern.search(clean):
                findings.append(
                    Finding(
                        id="SEC007",
                        analyzer=self.name,
                        category=self.category,
                        severity=Severity.HIGH,
                        description="Use of eval() function allows arbitrary code execution.",
                        file_path=rel_path,
                        line_number=line_idx,
                        evidence="eval(...)",
                        remediation="Refactor to avoid eval(). Use structured JSON parsing or safe handlers.",
                        confidence=Confidence.MEDIUM,
                    )
                )

            if shell_pattern.search(clean):
                findings.append(
                    Finding(
                        id="SEC006",
                        analyzer=self.name,
                        category=self.category,
                        severity=Severity.HIGH,
                        description="Use of shell=True in process execution may lead to command injection.",
                        file_path=rel_path,
                        line_number=line_idx,
                        evidence="shell: true",
                        remediation="Disable shell execution and pass executable arguments as an array.",
                        confidence=Confidence.MEDIUM,
                    )
                )

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """Never print complete secret values. Mask all but prefix and suffix."""
        if len(secret) <= 6:
            return "***"
        prefix = secret[:4]
        suffix = secret[-2:] if len(secret) > 10 else ""
        masked_length = len(secret) - len(prefix) - len(suffix)
        return f"{prefix}{'*' * min(masked_length, 12)}{suffix}"
