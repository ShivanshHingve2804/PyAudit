"""Baseline support for PyAudit findings."""

import json
import hashlib
import os

from pyaudit.models import AnalysisResult, Issue


def _fingerprint_material(
    rule_id: str,
    filepath: str,
    line: int,
    col: int,
    message: str,
) -> str:
    absolute_path = os.path.abspath(filepath)
    try:
        normalized_path = os.path.normpath(
            os.path.relpath(absolute_path, os.getcwd())
        )
    except ValueError:
        # Windows raises ValueError when the file and working directory are
        # on different drives. Keep the absolute path in that case so
        # fingerprint generation remains usable on CI runners.
        normalized_path = os.path.normpath(absolute_path)

    return "\0".join([
        rule_id,
        normalized_path,
        str(line),
        str(col),
        message,
    ])


def issue_fingerprint(issue: Issue) -> str:
    """Return a stable fingerprint for a finding."""
    material = _fingerprint_material(
        issue.rule_id,
        issue.filepath,
        issue.line,
        issue.col,
        issue.message,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _legacy_issue_fingerprint(issue_data: dict) -> str:
    """Recreate a fingerprint for baseline files without stored fingerprints."""
    material = _fingerprint_material(
        issue_data["rule_id"],
        issue_data["filepath"],
        issue_data["line"],
        issue_data["col"],
        issue_data["message"],
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def load_baseline_fingerprints(path: str) -> set[str]:
    """Load finding fingerprints from a JSON baseline/report file."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    fingerprints = set()
    for result in data.get("results", []):
        filepath = result.get("filepath", "")
        for issue in result.get("issues", []):
            fingerprint = issue.get("fingerprint")
            if fingerprint:
                fingerprints.add(fingerprint)
            else:
                issue_with_path = dict(issue)
                issue_with_path["filepath"] = filepath
                fingerprints.add(_legacy_issue_fingerprint(issue_with_path))

    return fingerprints


def filter_baseline_results(
    results: list[AnalysisResult],
    baseline_fingerprints: set[str],
) -> list[AnalysisResult]:
    """Remove findings already present in a baseline."""
    filtered = []
    for result in results:
        filtered.append(AnalysisResult(
            filepath=result.filepath,
            issues=[
                issue
                for issue in result.issues
                if issue_fingerprint(issue) not in baseline_fingerprints
            ],
            error=result.error,
        ))
    return filtered


def write_baseline(path: str, json_report: str) -> None:
    """Write a JSON report as a reusable baseline file."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json_report)
