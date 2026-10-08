"""CLI entry point for PyAudit.

Provides the `pyaudit` command with subcommands for scanning files
and directories for Python code quality issues.
"""

import sys
import argparse
import os

from pyaudit import __version__
from pyaudit.analyzer import analyze_path
from pyaudit.baseline import (
    filter_baseline_results,
    load_baseline_fingerprints,
    write_baseline,
)
from pyaudit.reporter import format_results, filter_results
from pyaudit.models import Severity


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="pyaudit",
        description="PyAudit — AST-based Python code quality analyzer",
        epilog="Example: pyaudit scan src/ --format json --severity high",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 'scan' subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan Python files for code quality issues",
        description="Analyze Python files or directories for bugs, security issues, and style problems.",
    )
    scan_parser.add_argument(
        "path",
        help="Path to a Python file or directory to scan",
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["table", "json", "summary", "sarif"],
        default="table",
        dest="output_format",
        help="Output format (default: table)",
    )
    scan_parser.add_argument(
        "--severity", "-s",
        choices=["high", "medium", "low", "all"],
        default="all",
        help="Filter issues by minimum severity (default: all)",
    )
    scan_parser.add_argument(
        "--category", "-c",
        choices=["bugs", "security", "style", "all"],
        default="all",
        help="Filter issues by category (default: all)",
    )
    scan_parser.add_argument(
        "--ignore",
        default="",
        metavar="RULES",
        help="Comma-separated rule IDs to ignore (e.g. PA-C003,PA-B004)",
    )

    baseline_group = scan_parser.add_mutually_exclusive_group()
    baseline_group.add_argument(
        "--baseline",
        metavar="PATH",
        help="Suppress findings already present in a JSON baseline file",
    )
    baseline_group.add_argument(
        "--write-baseline",
        metavar="PATH",
        help="Write current filtered findings to a JSON baseline and exit successfully",
    )

    # 'version' subcommand
    subparsers.add_parser(
        "version",
        help="Print PyAudit version",
    )

    return parser


def run_scan(args) -> int:
    """Execute the scan command.

    Returns:
        Exit code: 1 if high-severity issues found, 0 otherwise.
    """
    path = args.path

    # Validate path exists
    if not os.path.exists(path):
        print(f"\033[91mError: Path '{path}' does not exist.\033[0m", file=sys.stderr)
        return 2

    # Run analysis
    results = analyze_path(path)

    ignored_rules = [
        rule_id.strip()
        for rule_id in args.ignore.split(",")
        if rule_id.strip()
    ]

    # Apply CLI filters before baseline comparison.
    filtered_results = filter_results(
        results,
        severity_filter=args.severity,
        category_filter=args.category,
        ignored_rules=set(ignored_rules),
    )

    if args.baseline:
        try:
            baseline_fingerprints = load_baseline_fingerprints(args.baseline)
        except (OSError, ValueError, KeyError) as exc:
            print(
                f"\033[91mError: Could not read baseline '{args.baseline}': {exc}\033[0m",
                file=sys.stderr,
            )
            return 2

        filtered_results = filter_baseline_results(
            filtered_results,
            baseline_fingerprints,
        )

    if args.write_baseline:
        try:
            baseline_json = format_results(filtered_results, fmt="json")
            write_baseline(args.write_baseline, baseline_json)
        except OSError as exc:
            print(
                f"\033[91mError: Could not write baseline '{args.write_baseline}': {exc}\033[0m",
                file=sys.stderr,
            )
            return 2
        print(
            f"Baseline written to {args.write_baseline}",
            file=sys.stderr,
        )

    # Format and print output.
    output = format_results(filtered_results, fmt=args.output_format)
    print(output)

    # Determine exit code
    has_high = any(
        issue.severity == Severity.HIGH
        for result in filtered_results
        for issue in result.issues
    )
    if args.write_baseline:
        return 0
    return 1 if has_high else 0


def main() -> None:
    """Main entry point for the PyAudit CLI."""
    parser = create_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "version":
        print(f"PyAudit v{__version__}")
        sys.exit(0)

    if args.command == "scan":
        exit_code = run_scan(args)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
