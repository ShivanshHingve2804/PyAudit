"""Core analysis engine for PyAudit.

Orchestrates file parsing and rule execution to produce analysis results.
"""

import ast
from pyaudit.models import AnalysisResult
from pyaudit.rules import ALL_CHECKERS
from pyaudit.utils import collect_python_files, read_file_safe


def analyze_file(filepath: str) -> AnalysisResult:
    """Analyze a single Python file for code quality issues.

    Parses the file into an AST and runs all registered rule checkers.
    Handles syntax errors and I/O errors gracefully.

    Args:
        filepath: Absolute or relative path to a Python file.

    Returns:
        AnalysisResult with any issues found or an error message.
    """
    source, error = read_file_safe(filepath)
    if error:
        return AnalysisResult(filepath=filepath, error=error)

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        return AnalysisResult(
            filepath=filepath,
            error=f"Syntax error at line {e.lineno}: {e.msg}"
        )

    issues = []
    for checker in ALL_CHECKERS:
        issues.extend(checker(tree, filepath))

    # Sort issues by line number
    issues.sort(key=lambda i: (i.line, i.col))

    return AnalysisResult(filepath=filepath, issues=issues)


def analyze_path(path: str) -> list:
    """Analyze all Python files at the given path.

    If path is a file, analyzes just that file.
    If path is a directory, recursively discovers and analyzes all .py files.

    Args:
        path: Path to a Python file or directory.

    Returns:
        List of AnalysisResult objects, one per file analyzed.
    """
    files = collect_python_files(path)

    if not files:
        return [AnalysisResult(filepath=path, error=f"No Python files found at '{path}'")]

    results = []
    for filepath in files:
        result = analyze_file(filepath)
        results.append(result)

    return results
