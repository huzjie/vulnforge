"""Go-specific vulnerability detection rules (CWE-78/89/798)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="go-exec-concat",
        title="Go exec.Command with concatenation",
        description="exec.Command is built via string concatenation.",
        severity="high",
        patterns=[
            r"exec\.Command\s*\(\s*[^)]*\+",
            r"exec\.CommandContext\s*\([^)]*\+",
        ],
        cwe="CWE-78",
        recommendation="Pass arguments as separate strings, avoid shell interpolation.",
        extensions=[".go"],
    ),
    StaticRule(
        id="go-sql-concat",
        title="Go SQL query built by concatenation",
        description="A database query is built by concatenating SQL with input.",
        severity="high",
        patterns=[
            r'(?i)(db\.Query|db\.Exec|db\.QueryRow)\s*\(\s*["\'][^"\']*(SELECT|INSERT|UPDATE|DELETE)\b[^"\']*["\']\s*\+'
        ],
        cwe="CWE-89",
        recommendation="Use placeholders (?/$1) and pass arguments separately.",
        extensions=[".go"],
    ),
    StaticRule(
        id="go-sql-sprintf",
        title="Go SQL built with fmt.Sprintf",
        description="fmt.Sprintf interpolates values into a SQL string.",
        severity="high",
        patterns=[
            r'(?i)fmt\.Sprintf\s*\(\s*["\'][^"\']*(SELECT|INSERT|UPDATE|DELETE)\b'
        ],
        cwe="CWE-89",
        recommendation="Use parameterized queries with placeholders.",
        extensions=[".go"],
    ),
    StaticRule(
        id="go-hardcoded-secret",
        title="Go hardcoded credential",
        description="A Go credential-like variable is assigned a literal.",
        severity="high",
        patterns=[
            r"(?i)\b(password|secret|token|apiKey|api_key)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']"
        ],
        cwe="CWE-798",
        recommendation="Load credentials from environment or a secret store.",
        extensions=[".go"],
    ),
]

__all__ = ["RULES"]
