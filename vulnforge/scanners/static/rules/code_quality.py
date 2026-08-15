"""Code-quality / style heuristic rules (informational and low severity)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="quality-long-line",
        title="Overly long line",
        description="A source line exceeds the configured length limit.",
        severity="info",
        patterns=[r"^.{161,}$"],
        cwe="",
        recommendation="Break the line into multiple statements.",
    ),
    StaticRule(
        id="quality-bare-except",
        title="Bare except clause",
        description="A bare 'except:' swallows all exceptions, hiding errors.",
        severity="low",
        patterns=[r"(?i)except\s*:"],
        cwe="",
        recommendation="Catch specific exception types.",
        extensions=[".py"],
    ),
    StaticRule(
        id="quality-todo",
        title="TODO/FIXME marker",
        description="A TODO/FIXME/HACK/XXX marker indicates incomplete work.",
        severity="info",
        patterns=[r"(?i)\b(TODO|FIXME|XXX|HACK)\b"],
        cwe="",
        recommendation="Resolve or track the outstanding item.",
    ),
    StaticRule(
        id="quality-debug-output",
        title="Debug output statement",
        description="A debug print / console.log / var_dump statement was found.",
        severity="info",
        patterns=[
            r"(?i)\bconsole\.log\s*\(",
            r"(?i)\bprint\s*\(",
            r"(?i)System\.out\.println\s*\(",
            r"(?i)\bvar_dump\s*\(",
            r"\bdebugger\s*;",
        ],
        cwe="",
        recommendation="Remove debug statements before release.",
    ),
    StaticRule(
        id="quality-hardcoded-ip",
        title="Hardcoded IP address",
        description="A literal IPv4 address was found in source.",
        severity="low",
        patterns=[
            r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ],
        cwe="",
        recommendation="Prefer hostnames or configuration for network addresses.",
    ),
]

__all__ = ["RULES"]
