"""CVSS 3.1 base score calculation (official FIRST formula).

Implements the 3.1 base metric scoring algorithm entirely with the standard
library: Impact Sub-Score (ISC), Impact, Exploitability, Scope adjustment
(``1.08`` multiplier) and the ``Roundup`` helper.
"""

from __future__ import annotations

import math
from typing import Dict, Optional, Union

from .vectors import DEFAULTS, METRICS, VALID_METRICS


def parse_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS 3.1 vector string into a metric dict.

    Args:
        vector: A vector such as
            ``"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"``.

    Returns:
        A dict mapping uppercase metric names to uppercase values, e.g.
        ``{"AV": "N", "AC": "L", ...}``.  Unknown / malformed segments are
        ignored.
    """
    result: Dict[str, str] = {}
    if not vector:
        return result
    for segment in str(vector).strip().split("/"):
        if ":" not in segment:
            continue
        key, _, value = segment.partition(":")
        key = key.strip().upper()
        value = value.strip().upper()
        if key in VALID_METRICS and value:
            result[key] = value
    return result


def _metric_value(metrics: Dict[str, str], key: str, scope: str = "U") -> float:
    """Resolve the numeric weight for a metric, applying defaults."""
    value = metrics.get(key, DEFAULTS[key]).upper()
    table = METRICS[key]
    weight: Union[float, Dict[str, float]] = table.get(value, table[DEFAULTS[key]])
    if isinstance(weight, dict):
        return weight.get(scope, weight["U"])
    return float(weight)


def _roundup(value: float) -> float:
    """Round up to the nearest 0.1 (CVSS 3.1 Roundup function)."""
    return math.ceil(value * 10.0) / 10.0


def score_cvss31(vector: str) -> float:
    """Compute the CVSS 3.1 base score for a vector string.

    Args:
        vector: A CVSS 3.1 vector string.

    Returns:
        A base score in the range ``0.0`` to ``10.0``.
    """
    metrics = parse_vector(vector)
    scope = metrics.get("S", DEFAULTS["S"]).upper()

    c = _metric_value(metrics, "C")
    i = _metric_value(metrics, "I")
    a = _metric_value(metrics, "A")

    # Impact Sub-Score (ISC).
    isc_base = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    if impact <= 0.0:
        return 0.0

    # Exploitability.
    av = _metric_value(metrics, "AV")
    ac = _metric_value(metrics, "AC")
    pr = _metric_value(metrics, "PR", scope)
    ui = _metric_value(metrics, "UI")
    exploitability = 8.22 * av * ac * pr * ui

    if scope == "U":
        base = impact + exploitability
    else:
        base = 1.08 * (impact + exploitability)

    base = min(base, 10.0)
    return _roundup(base)


def severity_from_cvss(score: Optional[float]) -> str:
    """Map a CVSS base score to its qualitative severity rating.

    Args:
        score: A numeric base score (0.0-10.0).

    Returns:
        One of ``none``, ``low``, ``medium``, ``high``, ``critical``.
    """
    if score is None:
        return "none"
    score = float(score)
    if score <= 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


__all__ = ["parse_vector", "score_cvss31", "severity_from_cvss"]
