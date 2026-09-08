"""Code style checking rules using AST analysis.

Rules:
    PA-C001: Function too long (>50 statements)
    PA-C002: Too many arguments (>5 excluding self/cls)
    PA-C003: Missing docstring in public function/class
    PA-C004: Too many return statements (>5)
    PA-C005: Deeply nested code (>4 levels)
    PA-C006: Star import (from module import *)
"""

import ast
from pyaudit.models import Issue, Severity, Category


class StyleChecker(ast.NodeVisitor):
    """AST visitor that checks code style and complexity."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.issues: list[Issue] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Skip private/protected methods for docstring checks
        is_public = not node.name.startswith("_")

        # PA-C001: Function too long
        body_statements = self._count_statements(node.body)
        if body_statements > 50:
            self.issues.append(Issue(
                rule_id="PA-C001",
                message=f"Function '{node.name}' is too long ({body_statements} statements, max 50)",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.LOW,
                category=Category.STYLE,
                suggestion="Break this function into smaller, focused functions"
            ))

        # PA-C002: Too many arguments
        args = node.args
        param_count = len(args.args) + len(args.posonlyargs) + len(args.kwonlyargs)
        # Exclude self/cls
        if args.args and args.args[0].arg in ("self", "cls"):
            param_count -= 1
        if param_count > 5:
            self.issues.append(Issue(
                rule_id="PA-C002",
                message=f"Function '{node.name}' has too many arguments ({param_count}, max 5)",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.LOW,
                category=Category.STYLE,
                suggestion="Consider using a dataclass, dict, or **kwargs to reduce parameter count"
            ))

        # PA-C003: Missing docstring
        if is_public and not self._has_docstring(node):
            self.issues.append(Issue(
                rule_id="PA-C003",
                message=f"Missing docstring in public function '{node.name}'",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.LOW,
                category=Category.STYLE,
                suggestion="Add a docstring describing the function's purpose, parameters, and return value"
            ))

        # PA-C004: Too many return statements
        return_count = self._count_returns(node)
        if return_count > 5:
            self.issues.append(Issue(
                rule_id="PA-C004",
                message=f"Function '{node.name}' has too many return statements ({return_count}, max 5)",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.LOW,
                category=Category.STYLE,
                suggestion="Simplify the control flow or extract helper functions"
            ))

        # PA-C005: Deeply nested code
        max_depth = self._max_nesting_depth(node.body, current_depth=0)
        if max_depth > 4:
            self.issues.append(Issue(
                rule_id="PA-C005",
                message=f"Function '{node.name}' has deeply nested code (depth {max_depth}, max 4)",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.MEDIUM,
                category=Category.STYLE,
                suggestion="Use early returns, guard clauses, or extract nested logic into helper functions"
            ))

        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # PA-C003: Missing docstring in public class
        if not node.name.startswith("_") and not self._has_docstring(node):
            self.issues.append(Issue(
                rule_id="PA-C003",
                message=f"Missing docstring in public class '{node.name}'",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.LOW,
                category=Category.STYLE,
                suggestion="Add a docstring describing the class's purpose and usage"
            ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # PA-C006: Star import
        if node.names and any(alias.name == "*" for alias in node.names):
            module = node.module or "<unknown>"
            self.issues.append(Issue(
                rule_id="PA-C006",
                message=f"Star import 'from {module} import *' pollutes the namespace",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.LOW,
                category=Category.STYLE,
                suggestion=f"Import specific names from '{module}' instead"
            ))
        self.generic_visit(node)

    def _has_docstring(self, node) -> bool:
        """Check if a function or class has a docstring."""
        if node.body and isinstance(node.body[0], ast.Expr):
            if isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
                return True
        return False

    def _count_statements(self, body: list) -> int:
        """Recursively count all statements in a body."""
        count = 0
        for node in body:
            count += 1
            for child_body_attr in ("body", "orelse", "finalbody", "handlers"):
                child_body = getattr(node, child_body_attr, None)
                if isinstance(child_body, list):
                    count += self._count_statements(child_body)
        return count

    def _count_returns(self, node: ast.FunctionDef) -> int:
        """Count return statements in a function (not nested functions)."""
        count = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                count += 1
            # Don't count returns in nested functions
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child is not node:
                continue
        return count

    def _max_nesting_depth(self, body: list, current_depth: int) -> int:
        """Calculate the maximum nesting depth of control flow statements."""
        max_depth = current_depth
        nesting_nodes = (ast.If, ast.For, ast.While, ast.With, ast.Try,
                         ast.AsyncFor, ast.AsyncWith)
        for node in body:
            if isinstance(node, nesting_nodes):
                for child_body_attr in ("body", "orelse", "finalbody", "handlers"):
                    child_body = getattr(node, child_body_attr, None)
                    if isinstance(child_body, list) and child_body:
                        depth = self._max_nesting_depth(child_body, current_depth + 1)
                        max_depth = max(max_depth, depth)
        return max_depth


def check(tree: ast.Module, filepath: str) -> list:
    """Run all style checking rules on an AST.

    Args:
        tree: Parsed AST module.
        filepath: Path to the source file (for reporting).

    Returns:
        List of Issue objects found.
    """
    checker = StyleChecker(filepath)
    checker.visit(tree)
    return checker.issues
