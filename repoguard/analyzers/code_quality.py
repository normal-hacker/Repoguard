"""Code quality analyzer inspecting file sizes, function complexity, and maintainability."""

from __future__ import annotations

import ast

from repoguard.core.context import ScanContext
from repoguard.core.findings import Category, Confidence, Finding, Severity
from repoguard.plugins.base import BaseAnalyzer


class CyclomaticComplexityVisitor(ast.NodeVisitor):
    """Calculates McCabe cyclomatic complexity for an AST function node."""

    def __init__(self) -> None:
        self.complexity = 1

    def visit_If(self, node: ast.If) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.complexity += len(node.values) - 1
        self.generic_visit(node)


class CodeQualityAnalyzer(BaseAnalyzer):
    """Inspects code maintainability: large files, complex functions, and poor patterns."""

    name = "code_quality"
    description = (
        "Checks for oversized files, high cyclomatic complexity, and maintainability antipatterns"
    )
    category = Category.CODE_QUALITY
    version = "1.0.0"

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        limits = context.config.code_quality

        python_files = context.list_files(extension=".py")
        for file_path in python_files:
            rel_path = context.get_relative_path(file_path)
            content = context.read_file(file_path)
            if content is None:
                continue

            lines = content.splitlines()

            # 1. Check file size
            if len(lines) > limits.max_file_lines:
                findings.append(
                    Finding(
                        id="QUAL001",
                        analyzer=self.name,
                        category=self.category,
                        severity=Severity.LOW,
                        description=f"File exceeds maximum recommended length ({len(lines)} > {limits.max_file_lines} lines).",
                        file_path=rel_path,
                        remediation="Decompose this module into smaller, focused single-responsibility files.",
                        confidence=Confidence.HIGH,
                        metadata={"lines": len(lines), "max": limits.max_file_lines},
                    )
                )

            # 2. Parse Python AST for modular quality checks
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                # Syntax errors will be reported or skipped safely
                continue

            self._analyze_python_ast(tree, rel_path, limits, findings)

        return findings

    def _analyze_python_ast(
        self,
        tree: ast.AST,
        rel_path: str,
        limits,
        findings: list[Finding],
    ) -> None:
        for node in ast.walk(tree):
            # Check wildcard imports
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        findings.append(
                            Finding(
                                id="QUAL002",
                                analyzer=self.name,
                                category=self.category,
                                severity=Severity.LOW,
                                description=f"Wildcard import 'from {node.module} import *' pollutes namespace.",
                                file_path=rel_path,
                                line_number=node.lineno,
                                remediation="Explicitly import required functions and classes instead of '*'.",
                                confidence=Confidence.HIGH,
                            )
                        )

            # Check function definitions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = node.name
                func_line = node.lineno
                func_length = (node.end_lineno - node.lineno + 1) if node.end_lineno else 1

                # Check function length
                if func_length > limits.max_function_lines:
                    findings.append(
                        Finding(
                            id="QUAL003",
                            analyzer=self.name,
                            category=self.category,
                            severity=Severity.LOW,
                            description=f"Function '{func_name}' is too long ({func_length} > {limits.max_function_lines} lines).",
                            file_path=rel_path,
                            line_number=func_line,
                            remediation="Refactor the function into smaller helper functions.",
                            confidence=Confidence.HIGH,
                            metadata={"length": func_length, "max": limits.max_function_lines},
                        )
                    )

                # Check argument count
                total_args = (
                    len(node.args.args) + len(node.args.posonlyargs) + len(node.args.kwonlyargs)
                )
                if total_args > limits.max_function_arguments:
                    findings.append(
                        Finding(
                            id="QUAL004",
                            analyzer=self.name,
                            category=self.category,
                            severity=Severity.LOW,
                            description=f"Function '{func_name}' has excessive parameters ({total_args} > {limits.max_function_arguments}).",
                            file_path=rel_path,
                            line_number=func_line,
                            remediation="Group related parameters into a configuration model, dataclass, or object.",
                            confidence=Confidence.MEDIUM,
                            metadata={"args": total_args, "max": limits.max_function_arguments},
                        )
                    )

                # Calculate cyclomatic complexity
                visitor = CyclomaticComplexityVisitor()
                # Visit function body directly
                for stmt in node.body:
                    visitor.visit(stmt)
                complexity = visitor.complexity

                if complexity > limits.max_cyclomatic_complexity:
                    findings.append(
                        Finding(
                            id="QUAL005",
                            analyzer=self.name,
                            category=self.category,
                            severity=Severity.MEDIUM,
                            description=f"Function '{func_name}' has high cyclomatic complexity ({complexity} > {limits.max_cyclomatic_complexity}).",
                            file_path=rel_path,
                            line_number=func_line,
                            remediation="Simplify conditionals and extract branching logic into separate functions.",
                            confidence=Confidence.HIGH,
                            metadata={
                                "complexity": complexity,
                                "max": limits.max_cyclomatic_complexity,
                            },
                        )
                    )
