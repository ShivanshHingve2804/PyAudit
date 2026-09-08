"""Utility functions for PyAudit - file discovery, I/O, and terminal colors."""

import os
from pathlib import Path
from typing import Optional

# ANSI color codes for terminal output
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
WHITE = "\033[97m"

# Directories to skip during recursive file discovery
SKIP_DIRS = {
    "__pycache__", ".git", ".venv", "venv", "node_modules",
    ".tox", ".eggs", ".mypy_cache", ".pytest_cache", "dist",
    "build", ".hg", ".svn", "ENV", "env",
}


def colorize(text: str, color: str) -> str:
    """Wrap text in ANSI color codes."""
    return f"{color}{text}{RESET}"


def severity_color(severity_value: str) -> str:
    """Return the ANSI color code for a given severity level."""
    colors = {
        "high": RED,
        "medium": YELLOW,
        "low": CYAN,
    }
    return colors.get(severity_value, WHITE)


def collect_python_files(path: str) -> list:
    """Recursively find all .py files under a path, skipping ignored directories.

    Args:
        path: A file path or directory path to search.

    Returns:
        A sorted list of absolute paths to Python files.
    """
    target = Path(path).resolve()

    if target.is_file():
        if target.suffix == ".py":
            return [str(target)]
        return []

    if not target.is_dir():
        return []

    python_files = []
    for root, dirs, files in os.walk(target):
        # Prune ignored directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]

        for filename in sorted(files):
            if filename.endswith(".py"):
                python_files.append(os.path.join(root, filename))

    return sorted(python_files)


def read_file_safe(filepath: str) -> tuple:
    """Safely read a file, returning (content, error_message).

    Args:
        filepath: Path to the file to read.

    Returns:
        Tuple of (file_content, None) on success, or (None, error_message) on failure.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), None
    except FileNotFoundError:
        return None, f"File not found: {filepath}"
    except PermissionError:
        return None, f"Permission denied: {filepath}"
    except OSError as e:
        return None, f"Error reading {filepath}: {e}"
