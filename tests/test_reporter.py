"""Tests for the reporter module."""

import json
from pyaudit.models import AnalysisResult, Issue, Severity, Category
from pyaudit.reporter import format_results, print_summary


def _make_result():
    issues = [
        Issue("PA-S001", "eval() detected", "test.py", 5, 0, Severity.HIGH, Category.SECURITY),
        Issue("PA-B001", "Mutable default", "test.py", 10, 0, Severity.MEDIUM, Category.BUG),
        Issue("PA-C003", "Missing docstring", "test.py", 1, 0, Severity.LOW, Category.STYLE),
    ]
    return [AnalysisResult(filepath="test.py", issues=issues)]


def test_json_output_valid():
    results = _make_result()
    output = format_results(results, fmt="json")
    parsed = json.loads(output)
    assert "results" in parsed
    assert "summary" in parsed
    assert parsed["summary"]["total_issues"] == 3


def test_table_output_contains_rules():
    results = _make_result()
    output = format_results(results, fmt="table")
    assert "PA-S001" in output
    assert "PA-B001" in output


def test_summary_output():
    results = _make_result()
    output = format_results(results, fmt="summary")
    assert "3" in output


def test_severity_filter():
    results = _make_result()
    output = format_results(results, fmt="json", severity_filter="high")
    parsed = json.loads(output)
    issues = parsed["results"][0]["issues"]
    assert len(issues) == 1
    assert issues[0]["severity"] == "high"


def test_category_filter():
    results = _make_result()
    output = format_results(results, fmt="json", category_filter="security")
    parsed = json.loads(output)
    issues = parsed["results"][0]["issues"]
    assert len(issues) == 1
    assert issues[0]["category"] == "security"


def test_empty_results():
    results = [AnalysisResult(filepath="clean.py", issues=[])]
    summary = print_summary(results)
    assert "No issues" in summary
