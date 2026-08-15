"""Static analysis rule data model."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class StaticRule:
    """A single regex-based static analysis rule.

    Attributes:
        id: Unique rule identifier (e.g. ``"secrets-aws-access-key"``).
        title: Short human-readable title.
        description: Longer explanation of the issue.
        severity: Severity string (``info``..``critical``).
        patterns: List of regular expressions to search for.
        cwe: Associated CWE id (may be empty for style rules).
        recommendation: Suggested remediation.
        extensions: Optional list of file extensions to limit the rule to;
            ``None`` (default) applies to all files.
        multiline: When ``True``, patterns are searched across the entire file
            rather than line-by-line.
        flags: ``re`` flags applied to each pattern (default IGNORECASE).
    """

    id: str
    title: str
    description: str
    severity: str
    patterns: List[str]
    cwe: str = ""
    recommendation: str = ""
    extensions: Optional[List[str]] = None
    multiline: bool = False
    flags: int = re.IGNORECASE


__all__ = ["StaticRule"]
