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


def test_scan_ignore_rule():
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write("x = eval('1')\n")
    try:
        result = _run_pyaudit("scan", path, "--ignore", "PA-S001")
        assert result.returncode == 0
        assert "PA-S001" not in result.stdout
    finally:
        os.unlink(path)


def test_scan_high_severity_exit_respects_category_filter():
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write("eval('1')\n")
    try:
        result = _run_pyaudit("scan", path, "--category", "bugs")
        assert result.returncode == 0
        assert "PA-S001" not in result.stdout
    finally:
        os.unlink(path)


def test_scan_sarif_format():
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write("x = eval('1')\n")
    try:
        result = _run_pyaudit("scan", path, "--format", "sarif")
        assert result.returncode == 1
        import json
        parsed = json.loads(result.stdout)
        assert parsed["version"] == "2.1.0"
        assert parsed["runs"][0]["results"][0]["ruleId"] == "PA-S001"
        assert "partialFingerprints" in parsed["runs"][0]["results"][0]
    finally:
        os.unlink(path)


def test_scan_write_and_apply_baseline():
    fd, path = tempfile.mkstemp(suffix=".py")
    os.close(fd)
    baseline_path = path + ".baseline.json"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("x = eval('1')\n")

        write_result = _run_pyaudit(
            "scan",
            path,
            "--format",
            "json",
            "--write-baseline",
            baseline_path,
        )
        assert write_result.returncode == 0
        assert os.path.exists(baseline_path)

        baseline_result = _run_pyaudit(
            "scan",
            path,
            "--format",
            "json",
            "--baseline",
            baseline_path,
        )
        assert baseline_result.returncode == 0

        import json
        parsed = json.loads(baseline_result.stdout)
        assert parsed["summary"]["total_issues"] == 0
    finally:
        if os.path.exists(path):
            os.unlink(path)
        if os.path.exists(baseline_path):
            os.unlink(baseline_path)


def test_scan_missing_baseline():
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write("x = 1\n")
    try:
        result = _run_pyaudit(
            "scan",
            path,
            "--baseline",
            path + ".missing.json",
        )
        assert result.returncode == 2
        assert "baseline" in result.stderr.lower()
    finally:
        os.unlink(path)
