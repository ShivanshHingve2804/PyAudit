"""Output formatting for PyAudit analysis results.

Supports three output formats: table (colored terminal), JSON, and summary.
"""

import json
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
    filtered_results = _apply_filters(results, severity_filter, category_filter)

    if fmt == "json":
        return _format_json(filtered_results)
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
    lines.append(f"\n{BOLD}📊 Summary{RESET}")
    lines.append(f"   Files scanned: {files_scanned}")

    if errors:
        lines.append(f"   Errors: {colorize(str(len(errors)), RED)}")

    if total == 0:
        lines.append(f"   {colorize('✅ No issues found!', GREEN)}")
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


def _apply_filters(results: list, severity_filter: str, category_filter: str) -> list:
    """Filter results by severity and/or category."""
    if severity_filter == "all" and category_filter == "all":
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
            lines.append(f"\n{colorize('⚠', YELLOW)}  {colorize(result.filepath, BOLD)}")
            lines.append(f"   {colorize(result.error, RED)}")
            continue

        if not result.issues:
            continue

        lines.append(f"\n{colorize('📁', WHITE)} {colorize(result.filepath, BOLD)}")
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
                }
                for issue in result.issues
            ],
        }
        output["results"].append(file_data)

    return json.dumps(output, indent=2)


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
