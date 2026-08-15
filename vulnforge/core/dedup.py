"""Finding de-duplication.

Multiple scanners (or overlapping rules) can flag the same location.  This
module collapses findings keyed by ``(rule_id, file_path, line)``, keeping
the most severe (then most confident) occurrence.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from ..models import Finding


def dedupe(findings: List[Finding]) -> List[Finding]:
    """De-duplicate findings by ``(rule_id, file_path, line)``.

    For duplicate keys, the finding with the highest severity is kept; on a
    severity tie, the one with the highest confidence wins.

    Args:
        findings: The raw, un-deduplicated findings.

    Returns:
        A list of unique findings (original order not guaranteed).
    """
    best: Dict[Tuple[str, str, int], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line)
        current = best.get(key)
        if current is None:
            best[key] = finding
            continue
        if finding.severity.rank > current.severity.rank:
            best[key] = finding
        elif (
            finding.severity.rank == current.severity.rank
            and finding.confidence > current.confidence
        ):
            best[key] = finding
    return list(best.values())


__all__ = ["dedupe"]
