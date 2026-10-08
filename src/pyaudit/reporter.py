"""Output formatting for PyAudit analysis results.

Supports four output formats: table (colored terminal), JSON, summary, and SARIF.
"""

import json
import os

from pyaudit import __version__
from pyaudit.baseline import issue_fingerprint
from pyaudit.models import AnalysisResult, Issue, Severity, Category
from pyaudit.utils import (
    RED, YELLOW, GREEN, CYAN, BOLD, DIM, RESET, WHITE,
    severity_color, colorize,
)


def format_results(
    results: list,
    fmt: str = "table",
    severity_filter: str = "all",
    category_filter: str = "all",
    ignored_rules: list | None = None,
) -> str:
    """Format analysis results into the specified output format.

    Args:
        results: List of AnalysisResult objects.
        fmt: Output format - 'table', 'json', or 'summary'.
        severity_filter: Filter by severity ('high', 'medium', 'low', 'all').
        category_filter: Filter by category ('bugs', 'security', 'style', 'all').

    Returns:
        Formatted string output.
    """
    # Apply filters
    filtered_results = filter_results(
        results,
        severity_filter,
        category_filter,
        set(ignored_rules or []),
    )

    if fmt == "json":
        return _format_json(filtered_results)
    elif fmt == "sarif":
        return _format_sarif(filtered_results)
    elif fmt == "summary":
        return print_summary(filtered_results)
    else:
        return _format_table(filtered_results)


def print_summary(results: list) -> str:
    """Generate a summary line showing issue counts by severity.

    Args:
        results: List of AnalysisResult objects.

    Returns:
        Summary string with counts.
    """
    all_issues = []
    errors = []
    for r in results:
        all_issues.extend(r.issues)
        if r.error:
            errors.append(r.error)

    total = len(all_issues)
    high = sum(1 for i in all_issues if i.severity == Severity.HIGH)
    medium = sum(1 for i in all_issues if i.severity == Severity.MEDIUM)
    low = sum(1 for i in all_issues if i.severity == Severity.LOW)

    files_scanned = len(results)

    lines = []
    lines.append(f"\n{BOLD} Summary{RESET}")
    lines.append(f"   Files scanned: {files_scanned}")

    if errors:
        lines.append(f"   Errors: {colorize(str(len(errors)), RED)}")

    if total == 0:
        lines.append(f"   {colorize('No issues found! :)', GREEN)}")
    else:
        parts = []
        if high:
            parts.append(colorize(f"{high} high", RED))
        if medium:
            parts.append(colorize(f"{medium} medium", YELLOW))
        if low:
            parts.append(colorize(f"{low} low", CYAN))

        lines.append(f"   Issues found: {BOLD}{total}{RESET} ({', '.join(parts)})")

    return "\n".join(lines)


def filter_results(
    results: list,
    severity_filter: str,
    category_filter: str,
    ignored_rules: set[str] | None = None,
) -> list:
    """Filter results by severity and/or category."""
    ignored_rules = ignored_rules or set()

    if severity_filter == "all" and category_filter == "all" and not ignored_rules:
        return results

    category_map = {
        "bugs": Category.BUG,
        "bug": Category.BUG,
        "security": Category.SECURITY,
        "style": Category.STYLE,
    }

    filtered = []
    for result in results:
        new_issues = []
        for issue in result.issues:
            if issue.rule_id in ignored_rules:
                continue
            if severity_filter != "all" and issue.severity.value != severity_filter:
                continue
            if category_filter != "all":
                target_cat = category_map.get(category_filter)
                if target_cat and issue.category != target_cat:
                    continue
            new_issues.append(issue)
        filtered.append(AnalysisResult(
            filepath=result.filepath,
            issues=new_issues,
            error=result.error,
        ))

    return filtered


def _format_table(results: list) -> str:
    """Format results as a colored terminal table grouped by file."""
    lines = []
    separator = "─" * 80

    for result in results:
        if result.error:
            lines.append(f"\n{colorize('!', YELLOW)}  {colorize(result.filepath, BOLD)}")
            lines.append(f"   {colorize(result.error, RED)}")
            continue

        if not result.issues:
            continue

        lines.append(f"\n{colorize('FILE', WHITE)} {colorize(result.filepath, BOLD)}")
        lines.append(colorize(separator, DIM))

        # Header
        header = f"  {'Line':>6}  │ {'Col':>3} │ {'Severity':^10} │ {'Rule':^8} │ Message"
        lines.append(colorize(header, DIM))
        lines.append(colorize(f"  {'─'*6}──┼─{'─'*3}─┼─{'─'*10}─┼─{'─'*8}─┼─{'─'*40}", DIM))

        for issue in result.issues:
            sev_str = issue.severity.value.upper()
            color = severity_color(issue.severity.value)
            sev_display = colorize(f"{sev_str:^10}", color)

            line = f"  {issue.line:>6}  │ {issue.col:>3} │ {sev_display} │ {issue.rule_id:^8} │ {issue.message}"
            lines.append(line)

        lines.append(colorize(separator, DIM))

    lines.append(print_summary(results))

    return "\n".join(lines)


def _format_json(results: list) -> str:
    """Format results as structured JSON."""
    output = {
        "results": [],
        "summary": _get_summary_dict(results),
    }

    for result in results:
        file_data = {
            "filepath": result.filepath,
            "error": result.error,
            "issues": [
                {
                    "rule_id": issue.rule_id,
                    "message": issue.message,
                    "line": issue.line,
                    "col": issue.col,
                    "severity": issue.severity.value,
                    "category": issue.category.value,
                    "suggestion": issue.suggestion,
                    "fingerprint": issue_fingerprint(issue),
                }
                for issue in result.issues
            ],
        }
        output["results"].append(file_data)

    return json.dumps(output, indent=2)


def _format_sarif(results: list) -> str:
    """Format findings as SARIF 2.1.0 for code-scanning integrations."""
    rule_map = {}
    sarif_results = []

    level_map = {
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }

    for result in results:
        if result.error:
            continue

        for issue in result.issues:
            rule_map.setdefault(issue.rule_id, {
                "id": issue.rule_id,
                "name": issue.rule_id,
                "shortDescription": {"text": issue.message},
                "defaultConfiguration": {
                    "level": level_map[issue.severity],
                },
                "properties": {
                    "category": issue.category.value,
                },
            })

            result_data = {
                "ruleId": issue.rule_id,
                "level": level_map[issue.severity],
                "message": {"text": issue.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": os.path.relpath(
                                os.path.abspath(issue.filepath),
                                os.getcwd(),
                            ).replace(os.sep, "/"),
                        },
                        "region": {
                            "startLine": max(1, issue.line),
                            "startColumn": max(1, issue.col + 1),
                        },
                    }
                }],
                "partialFingerprints": {
                    "pyaudit/v1": issue_fingerprint(issue),
                },
            }

            if issue.suggestion:
                result_data["properties"] = {"suggestion": issue.suggestion}

            sarif_results.append(result_data)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PyAudit",
                    "version": __version__,
                    "rules": list(rule_map.values()),
                }
            },
            "results": sarif_results,
        }],
    }
    return json.dumps(payload, indent=2)


def _get_summary_dict(results: list) -> dict:
    """Generate summary statistics as a dictionary."""
    all_issues = []
    for r in results:
        all_issues.extend(r.issues)

    return {
        "files_scanned": len(results),
        "total_issues": len(all_issues),
        "high": sum(1 for i in all_issues if i.severity == Severity.HIGH),
        "medium": sum(1 for i in all_issues if i.severity == Severity.MEDIUM),
        "low": sum(1 for i in all_issues if i.severity == Severity.LOW),
        "by_category": {
            "bugs": sum(1 for i in all_issues if i.category == Category.BUG),
            "security": sum(1 for i in all_issues if i.category == Category.SECURITY),
            "style": sum(1 for i in all_issues if i.category == Category.STYLE),
        },
    }
