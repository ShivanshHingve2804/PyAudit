"""Rule engine for PyAudit. Each rule module exposes a check(tree, filepath) function."""

from pyaudit.rules.bug_detector import check as check_bugs
from pyaudit.rules.security_scanner import check as check_security
from pyaudit.rules.style_checker import check as check_style

ALL_CHECKERS = [check_bugs, check_security, check_style]
