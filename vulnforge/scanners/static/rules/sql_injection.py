"""SQL injection detection rules (CWE-89)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="sql-string-concat",
        title="SQL built via string concatenation",
        description="A SQL statement appears to be built with concatenation of user input.",
        severity="high",
        patterns=[
            r"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b[^\"']*\+[^\"']*\b(request|input|param|user|id|name|query|q)\b"
        ],
        cwe="CWE-89",
        recommendation="Use parameterized queries / prepared statements.",
    ),
    StaticRule(
        id="sql-fstring",
        title="SQL built via f-string interpolation",
        description="An f-string appears to interpolate variables into SQL.",
        severity="high",
        patterns=[r'(?i)f["\'][^"\']*(SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^"\']*\{'],
        cwe="CWE-89",
        recommendation="Use bound parameters instead of string interpolation.",
    ),
    StaticRule(
        id="sql-execute-concat",
        title="SQL execute with concatenation",
        description="A DB execute() call concatenates a SQL string with input.",
        severity="high",
        patterns=[
            r'(?i)\.execute\s*\(\s*["\'][^"\']*(SELECT|INSERT|UPDATE|DELETE)\b[^"\']*["\']\s*\+'
        ],
        cwe="CWE-89",
        recommendation="Pass parameters to execute() rather than concatenating.",
    ),
    StaticRule(
        id="sql-format-method",
        title="SQL built with format/percent",
        description="SQL built with .format() or %-style interpolation.",
        severity="high",
        patterns=[
            r'(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b[^"\']*["\']\s*\.format\(',
            r'(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b[^"\']*["\']\s*%\s*\(',
        ],
        cwe="CWE-89",
        recommendation="Use parameterized queries.",
    ),
    StaticRule(
        id="sql-query-concat",
        title="Query string concatenation",
        description="A query variable is built by concatenating a SQL string.",
        severity="medium",
        patterns=[
            r'(?i)query\s*=\s*["\'][^"\']*(SELECT|INSERT|UPDATE|DELETE)\b[^"\']*["\']\s*\+'
        ],
        cwe="CWE-89",
        recommendation="Use parameterized queries.",
    ),
]

__all__ = ["RULES"]
