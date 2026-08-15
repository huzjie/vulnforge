"""Core data models shared across the vulnforge codebase.

All other modules (core engine, scanners, reporters, CLI) import the
dataclasses and enums defined here.  The field names and signatures form a
stable public contract and must not be changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """Severity levels ordered from least to most severe."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Return an integer ordering weight (info=0 .. critical=4)."""
        return _SEVERITY_RANK[self]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Parse a severity from a string, falling back to ``INFO``."""
        if value is None:
            return cls.INFO
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.INFO

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Map a CVSS-style 0.0-10.0 numeric score to a Severity level."""
        if score <= 0.0:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL

    def __lt__(self, other: Any) -> bool:
        """Allow sorting by severity weight."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: Any) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: Any) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_RANK: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class Finding:
    """A single vulnerability or suspicious-code finding."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: str
    line: int  # 1-based line number
    column: int = 0
    code: str = ""
    cwe: str = ""
    cvss: Optional[float] = None
    confidence: float = 1.0
    scanner: str = "static"
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Target:
    """A scan target: a single file, a directory, or a repository."""

    path: str
    kind: str  # one of: file | directory | repo
    language: str = ""
    size: int = 0


@dataclass
class ScanResult:
    """Result of scanning a single target."""

    target: Target
    findings: List[Finding]
    duration_ms: int = 0
    error: str = ""


@dataclass
class ScanReport:
    """Aggregated report for an entire scan run."""

    scan_id: str
    created_at: str
    targets: List[Target]
    findings: List[Finding]
    stats: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)


__all__ = [
    "Severity",
    "Finding",
    "Target",
    "ScanResult",
    "ScanReport",
]
