"""CVSS 3.1 base metric weights and defaults.

The tables below reproduce the official FIRST CVSS v3.1 specification
weights for the six base metric groups used to compute the base score.
"""

from __future__ import annotations

from typing import Dict, Union

# Valid base metric names (case-insensitive).
VALID_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Default (worst-case) value for each metric when omitted from a vector.
DEFAULTS: Dict[str, str] = {
    "AV": "N",
    "AC": "L",
    "PR": "N",
    "UI": "N",
    "S": "U",
    "C": "H",
    "I": "H",
    "A": "H",
}

# Numeric weights per metric value.  PR depends on Scope (U/C).
METRICS: Dict[str, Dict[str, Union[float, Dict[str, float]]]] = {
    "AV": {
        "N": 0.85,
        "A": 0.62,
        "L": 0.55,
        "P": 0.2,
    },
    "AC": {
        "L": 0.77,
        "H": 0.44,
    },
    "PR": {
        "N": 0.85,
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.5},
    },
    "UI": {
        "N": 0.85,
        "R": 0.62,
    },
    "S": {
        "U": 0.0,  # scope weight is not used numerically; kept for reference
        "C": 0.0,
    },
    "C": {
        "H": 0.56,
        "L": 0.22,
        "N": 0.0,
    },
    "I": {
        "H": 0.56,
        "L": 0.22,
        "N": 0.0,
    },
    "A": {
        "H": 0.56,
        "L": 0.22,
        "N": 0.0,
    },
}

__all__ = ["VALID_METRICS", "DEFAULTS", "METRICS"]
