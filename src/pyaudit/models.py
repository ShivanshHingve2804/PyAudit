"""Data models for PyAudit analysis results."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Issue severity levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(Enum):
    """Issue category types."""
    BUG = "bug"
    SECURITY = "security"
    STYLE = "style"


@dataclass
class Issue:
    """Represents a single code quality issue found during analysis."""
    rule_id: str
    message: str
    filepath: str
    line: int
    col: int
    severity: Severity
    category: Category
    suggestion: Optional[str] = None


@dataclass
class AnalysisResult:
    """Result of analyzing a single file."""
    filepath: str
    issues: list = field(default_factory=list)
    error: Optional[str] = None
