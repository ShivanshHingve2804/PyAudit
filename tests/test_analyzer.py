"""Integration tests for the analyzer module."""

import os
import tempfile
from pyaudit.analyzer import analyze_file, analyze_path


def _create_temp_file(content: str, suffix=".py") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def test_analyze_file_finds_issues():
    path = _create_temp_file("def foo(x=[]):\n    eval('1+1')")
    try:
        result = analyze_file(path)
        assert result.error is None
        assert len(result.issues) > 0
    finally:
        os.unlink(path)


def test_analyze_file_syntax_error():
    path = _create_temp_file("def foo(\n")
    try:
        result = analyze_file(path)
        assert result.error is not None
        assert "Syntax error" in result.error
    finally:
        os.unlink(path)


def test_analyze_file_not_found():
    result = analyze_file("/nonexistent/path/file.py")
    assert result.error is not None
    assert "not found" in result.error.lower() or "No such file" in result.error


def test_analyze_path_directory():
    tmpdir = tempfile.mkdtemp()
    f1 = os.path.join(tmpdir, "a.py")
    f2 = os.path.join(tmpdir, "b.py")
    with open(f1, "w") as f:
        f.write("x = 1")
    with open(f2, "w") as f:
        f.write("y = 2")
    try:
        results = analyze_path(tmpdir)
        assert len(results) == 2
    finally:
        os.unlink(f1)
        os.unlink(f2)
        os.rmdir(tmpdir)


def test_analyze_path_single_file():
    path = _create_temp_file("x = 1\n")
    try:
        results = analyze_path(path)
        assert len(results) == 1
        assert os.path.realpath(results[0].filepath) == os.path.realpath(path)
    finally:
        os.unlink(path)


def test_analyze_clean_file():
    code = '"""Module docstring."""\n\ndef greet(name):\n    """Say hello."""\n    return f"Hello, {name}"\n'
    path = _create_temp_file(code)
    try:
        result = analyze_file(path)
        assert result.error is None
    finally:
        os.unlink(path)
