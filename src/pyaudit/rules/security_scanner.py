"""Security scanning rules using AST analysis.

Rules:
    PA-S001: Use of eval()
    PA-S002: Use of exec()
    PA-S003: Hardcoded password/secret
    PA-S004: Use of os.system() - command injection risk
    PA-S005: Use of pickle.loads() - deserialization vulnerability
    PA-S006: Use of weak hash algorithms (MD5/SHA1)
    PA-S007: SQL string formatting - injection risk
"""

import ast
from pyaudit.models import Issue, Severity, Category

# Variable names that suggest secrets
SECRET_PATTERNS = {
    "password", "passwd", "secret", "api_key", "apikey",
    "token", "private_key", "secret_key", "auth_token",
    "access_key", "credentials",
}

# SQL keywords to detect in f-strings / format calls
SQL_KEYWORDS = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE"}


class SecurityScanner(ast.NodeVisitor):
    """AST visitor that detects security vulnerabilities."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.issues: list[Issue] = []

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node)

        # PA-S001: Use of eval()
        if func_name == "eval":
            self.issues.append(Issue(
                rule_id="PA-S001",
                message="Use of eval() is a security risk — arbitrary code execution",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.HIGH,
                category=Category.SECURITY,
                suggestion="Use ast.literal_eval() for safe parsing, or avoid dynamic evaluation"
            ))

        # PA-S002: Use of exec()
        elif func_name == "exec":
            self.issues.append(Issue(
                rule_id="PA-S002",
                message="Use of exec() is a security risk — arbitrary code execution",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.HIGH,
                category=Category.SECURITY,
                suggestion="Avoid exec(); use safer alternatives for dynamic behavior"
            ))

        # PA-S004: Use of os.system()
        elif func_name in ("os.system", "system") and self._is_os_call(node, "system"):
            self.issues.append(Issue(
                rule_id="PA-S004",
                message="Use of os.system() — vulnerable to command injection",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.HIGH,
                category=Category.SECURITY,
                suggestion="Use subprocess.run() with a list of arguments instead"
            ))

        # PA-S005: Use of pickle.loads()
        elif func_name in ("pickle.loads", "pickle.load"):
            self.issues.append(Issue(
                rule_id="PA-S005",
                message=f"Use of {func_name}() — deserialization of untrusted data can execute arbitrary code",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.HIGH,
                category=Category.SECURITY,
                suggestion="Use JSON or another safe serialization format for untrusted data"
            ))

        # PA-S006: Weak hash algorithms
        elif func_name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1"):
            algo = "MD5" if "md5" in func_name else "SHA1"
            self.issues.append(Issue(
                rule_id="PA-S006",
                message=f"Use of weak hash algorithm {algo} — cryptographically broken",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                suggestion="Use hashlib.sha256() or hashlib.sha3_256() instead"
            ))

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # PA-S003: Hardcoded secrets
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_lower = target.id.lower()
                if any(pattern in var_lower for pattern in SECRET_PATTERNS):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 0:
                            self.issues.append(Issue(
                                rule_id="PA-S003",
                                message=f"Hardcoded secret in variable '{target.id}'",
                                filepath=self.filepath,
                                line=node.lineno,
                                col=node.col_offset,
                                severity=Severity.HIGH,
                                category=Category.SECURITY,
                                suggestion="Use environment variables or a secrets manager instead of hardcoding"
                            ))
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        # PA-S007: SQL injection via f-strings
        # Check if the f-string contains SQL keywords AND has interpolated values
        static_parts = []
        has_interpolation = False
        for value in node.values:
            if isinstance(value, ast.Constant):
                static_parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                has_interpolation = True

        if has_interpolation:
            combined = " ".join(static_parts).upper()
            for keyword in SQL_KEYWORDS:
                if keyword in combined:
                    self.issues.append(Issue(
                        rule_id="PA-S007",
                        message=f"SQL query built with f-string formatting — potential SQL injection",
                        filepath=self.filepath,
                        line=node.lineno,
                        col=node.col_offset,
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        suggestion="Use parameterized queries instead of string formatting"
                    ))
                    break

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract the full dotted name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _is_os_call(self, node: ast.Call, method: str) -> bool:
        """Check if a call is specifically os.method()."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == method and isinstance(node.func.value, ast.Name):
                return node.func.value.id == "os"
        return False


def check(tree: ast.Module, filepath: str) -> list:
    """Run all security scanning rules on an AST.

    Args:
        tree: Parsed AST module.
        filepath: Path to the source file (for reporting).

    Returns:
        List of Issue objects found.
    """
    scanner = SecurityScanner(filepath)
    scanner.visit(tree)
    return scanner.issues
