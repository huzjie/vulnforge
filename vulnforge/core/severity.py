"""Severity-aware ordering and filtering of findings."""

from __future__ import annotations

from typing import List, Optional

from ..models import Finding, Severity


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Sort findings by severity (desc) then location (asc).

    Args:
        findings: The findings to sort.

    Returns:
        A new list sorted by severity rank descending, then ``file_path`` and
        ``line`` ascending, then ``rule_id`` for stable ordering.
    """
    return sorted(
        findings,
        key=lambda f: (-f.severity.rank, f.file_path, f.line, f.rule_id),
    )


def filter_by_threshold(
    findings: List[Finding], min_sev: Optional[str]
) -> List[Finding]:
    """Keep only findings at or above a minimum severity.

    Args:
        findings: The findings to filter.
        min_sev: Minimum severity string (``info``..``critical``).  ``None``
            or empty means no filtering.

    Returns:
        A new list containing only findings meeting the threshold.
    """
    if not min_sev:
        return list(findings)
    threshold = Severity.from_str(min_sev).rank
    return [f for f in findings if f.severity.rank >= threshold]


__all__ = ["sort_findings", "filter_by_threshold"]
