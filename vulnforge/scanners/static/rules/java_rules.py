"""Java-specific vulnerability detection rules (CWE-89/502/78)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="java-sql-concat",
        title="Java SQL built by concatenation",
        description="A SQL statement string is concatenated with input.",
        severity="high",
        patterns=[
            r'(?i)(Statement|createStatement|prepareStatement)\s*\(?\s*["\'][^"\']*(SELECT|INSERT|UPDATE|DELETE)\b[^"\']*["\']\s*\+'
        ],
        cwe="CWE-89",
        recommendation="Use PreparedStatement with bound parameters.",
        extensions=[".java"],
    ),
    StaticRule(
        id="java-sql-execute",
        title="Java SQL execute with concatenation",
        description="execute/executeQuery/executeUpdate is called with concatenated SQL.",
        severity="high",
        patterns=[
            r'(?i)\.execute(?:Query|Update)?\s*\(\s*["\'][^"\']*(SELECT|INSERT|UPDATE|DELETE)\b[^"\']*["\']\s*\+'
        ],
        cwe="CWE-89",
        recommendation="Use PreparedStatement parameter binding.",
        extensions=[".java"],
    ),
    StaticRule(
        id="java-objectinputstream",
        title="Java unsafe deserialization",
        description="ObjectInputStream / readObject deserializes untrusted data.",
        severity="high",
        patterns=[r"\bObjectInputStream\s*\(", r"\breadObject\s*\("],
        cwe="CWE-502",
        recommendation="Validate serialized streams; avoid native deserialization.",
        extensions=[".java"],
    ),
    StaticRule(
        id="java-runtime-exec",
        title="Java Runtime.exec with concatenation",
        description="Runtime.getRuntime().exec() is called with a concatenated command.",
        severity="critical",
        patterns=[r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[^)]*\+"],
        cwe="CWE-78",
        recommendation="Use ProcessBuilder with an argument array.",
        extensions=[".java"],
    ),
    StaticRule(
        id="java-processbuilder",
        title="Java ProcessBuilder with concatenation",
        description="ProcessBuilder command is built via string concatenation.",
        severity="high",
        patterns=[r"new\s+ProcessBuilder\s*\([^)]*\+"],
        cwe="CWE-78",
        recommendation="Pass command arguments as separate strings.",
        extensions=[".java"],
    ),
]

__all__ = ["RULES"]
