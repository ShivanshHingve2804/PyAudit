"""CLI integration tests."""

import os
import sys
import tempfile
import subprocess


def _run_pyaudit(*args):
    """Run pyaudit CLI as a subprocess."""
    cmd = [sys.executable, "-m", "pyaudit.cli"] + list(args)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=os.path.join(os.path.dirname(__file__), ".."),
        env={**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "src"), "PYTHONUTF8": "1"},
    )
    return result


def test_version():
    result = _run_pyaudit("version")
    assert result.returncode == 0
    assert "PyAudit" in result.stdout


def test_scan_clean_file():
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write('"""Clean module."""\n\ndef greet(name):\n    """Say hi."""\n    return f"Hi {name}"\n')
    try:
        result = _run_pyaudit("scan", path)
        assert result.returncode == 0
    finally:
        os.unlink(path)


def test_scan_buggy_file_exit_code():
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write('eval(input())\npassword = "secret123"\n')
    try:
        result = _run_pyaudit("scan", path)
        assert result.returncode == 1
    finally:
        os.unlink(path)


def test_scan_json_format():
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write("x = eval('1')\n")
    try:
        result = _run_pyaudit("scan", path, "--format", "json")
        import json
        parsed = json.loads(result.stdout)
        assert "results" in parsed
    finally:
        os.unlink(path)


def test_scan_nonexistent_path():
    result = _run_pyaudit("scan", "/nonexistent/path.py")
    assert result.returncode != 0
