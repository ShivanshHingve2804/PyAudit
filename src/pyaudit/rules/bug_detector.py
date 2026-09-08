"""Bug detection rules using AST analysis.

Rules:
    PA-B001: Mutable default argument
    PA-B002: Bare except clause
    PA-B003: Comparison to None using == or !=
    PA-B004: Use of assert in non-test code
    PA-B005: Unused variables (basic function-scope detection)
    PA-B006: Return with value in __init__
    PA-B007: Redefining built-in names
"""

import ast
from pyaudit.models import Issue, Severity, Category

# Built-in names that should not be shadowed
BUILTINS = {
    "list", "dict", "str", "int", "set", "tuple", "type", "id", "input",
    "print", "len", "range", "map", "filter", "open", "zip", "sum",
    "min", "max", "abs", "all", "any", "format", "float", "bool",
    "bytes", "complex", "hash", "hex", "oct", "ord", "chr", "repr",
    "sorted", "reversed", "enumerate", "isinstance", "issubclass",
    "object", "property", "staticmethod", "classmethod", "super",
}


class BugDetector(ast.NodeVisitor):
    """AST visitor that detects common bug patterns."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.issues: list[Issue] = []
        self._current_function: str | None = None
        self._in_init = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev_func = self._current_function
        prev_init = self._in_init
        self._current_function = node.name
        self._in_init = node.name == "__init__"

        # PA-B001: Mutable default arguments
        self._check_mutable_defaults(node)

        # PA-B005: Unused variables (basic)
        self._check_unused_vars(node)

        self.generic_visit(node)
        self._current_function = prev_func
        self._in_init = prev_init

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        # PA-B002: Bare except clause
        if node.type is None:
            self.issues.append(Issue(
                rule_id="PA-B002",
                message="Bare except clause catches all exceptions including SystemExit and KeyboardInterrupt",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.MEDIUM,
                category=Category.BUG,
                suggestion="Specify the exception type, e.g., 'except Exception:'"
            ))
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        # PA-B003: Comparison to None using == or !=
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(comparator, ast.Constant) and comparator.value is None:
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    op_str = "==" if isinstance(op, ast.Eq) else "!="
                    fix_str = "is" if isinstance(op, ast.Eq) else "is not"
                    self.issues.append(Issue(
                        rule_id="PA-B003",
                        message=f"Comparison to None using '{op_str}' instead of '{fix_str}'",
                        filepath=self.filepath,
                        line=node.lineno,
                        col=node.col_offset,
                        severity=Severity.LOW,
                        category=Category.BUG,
                        suggestion=f"Use '{fix_str} None' instead of '{op_str} None'"
                    ))
            # Also check left side
        if isinstance(node.left, ast.Constant) and node.left.value is None:
            if node.ops and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
                op_str = "==" if isinstance(node.ops[0], ast.Eq) else "!="
                fix_str = "is" if isinstance(node.ops[0], ast.Eq) else "is not"
                self.issues.append(Issue(
                    rule_id="PA-B003",
                    message=f"Comparison to None using '{op_str}' instead of '{fix_str}'",
                    filepath=self.filepath,
                    line=node.lineno,
                    col=node.col_offset,
                    severity=Severity.LOW,
                    category=Category.BUG,
                    suggestion=f"Use '{fix_str} None' instead of '{op_str} None'"
                ))
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        # PA-B004: Use of assert in non-test code
        if not self.filepath.split("/")[-1].startswith("test_") and \
           not self.filepath.split("\\")[-1].startswith("test_"):
            self.issues.append(Issue(
                rule_id="PA-B004",
                message="Use of 'assert' statement — assertions are disabled with 'python -O'",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.LOW,
                category=Category.BUG,
                suggestion="Use explicit if/raise for runtime checks in production code"
            ))
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        # PA-B006: Return with value in __init__
        if self._in_init and node.value is not None:
            self.issues.append(Issue(
                rule_id="PA-B006",
                message="Return statement with a value in __init__ method",
                filepath=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity=Severity.MEDIUM,
                category=Category.BUG,
                suggestion="__init__ should not return a value; use 'return' without a value or remove it"
            ))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # PA-B007: Redefining built-in names
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in BUILTINS:
                self.issues.append(Issue(
                    rule_id="PA-B007",
                    message=f"Redefining built-in name '{target.id}'",
                    filepath=self.filepath,
                    line=node.lineno,
                    col=node.col_offset,
                    severity=Severity.MEDIUM,
                    category=Category.BUG,
                    suggestion=f"Use a different variable name instead of '{target.id}'"
                ))
        self.generic_visit(node)

    def _check_mutable_defaults(self, node: ast.FunctionDef) -> None:
        """Check for mutable default arguments (list, dict, set literals)."""
        for default in node.args.defaults + node.args.kw_defaults:
            if default is None:
                continue
            mutable_type = None
            if isinstance(default, ast.List):
                mutable_type = "list"
            elif isinstance(default, ast.Dict):
                mutable_type = "dict"
            elif isinstance(default, ast.Set):
                mutable_type = "set"
            elif isinstance(default, ast.Call):
                func_name = ""
                if isinstance(default.func, ast.Name):
                    func_name = default.func.id
                elif isinstance(default.func, ast.Attribute):
                    func_name = default.func.attr
                if func_name in ("list", "dict", "set"):
                    mutable_type = func_name

            if mutable_type:
                self.issues.append(Issue(
                    rule_id="PA-B001",
                    message=f"Mutable default argument of type '{mutable_type}'",
                    filepath=self.filepath,
                    line=default.lineno,
                    col=default.col_offset,
                    severity=Severity.MEDIUM,
                    category=Category.BUG,
                    suggestion="Use None as default and initialize inside the function body"
                ))

    def _check_unused_vars(self, node: ast.FunctionDef) -> None:
        """Basic unused variable detection within function scope."""
        # Collect all assignments (Name targets in Assign nodes)
        assigned = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and not target.id.startswith("_"):
                        assigned[target.id] = child

        # Collect all Name loads (references)
        referenced = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                referenced.add(child.id)

        # Also count augmented assignments and function args as references
        for child in ast.walk(node):
            if isinstance(child, ast.AugAssign):
                if isinstance(child.target, ast.Name):
                    referenced.add(child.target.id)

        # Exclude function arguments from unused detection
        arg_names = set()
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            arg_names.add(arg.arg)
        if node.args.vararg:
            arg_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            arg_names.add(node.args.kwarg.arg)

        for var_name, assign_node in assigned.items():
            if var_name not in referenced and var_name not in arg_names:
                self.issues.append(Issue(
                    rule_id="PA-B005",
                    message=f"Variable '{var_name}' is assigned but never used",
                    filepath=self.filepath,
                    line=assign_node.lineno,
                    col=assign_node.col_offset,
                    severity=Severity.MEDIUM,
                    category=Category.BUG,
                    suggestion=f"Remove the unused variable or prefix with '_' to indicate intentional non-use"
                ))


def check(tree: ast.Module, filepath: str) -> list:
    """Run all bug detection rules on an AST.

    Args:
        tree: Parsed AST module.
        filepath: Path to the source file (for reporting).

    Returns:
        List of Issue objects found.
    """
    detector = BugDetector(filepath)
    detector.visit(tree)
    return detector.issues
