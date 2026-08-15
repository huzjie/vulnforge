"""CVSS 3.1 vector parsing and scoring sub-package."""

from .calculator import parse_vector, score_cvss31, severity_from_cvss
from .vectors import METRICS, DEFAULTS, VALID_METRICS

__all__ = [
    "parse_vector",
    "score_cvss31",
    "severity_from_cvss",
    "METRICS",
    "DEFAULTS",
    "VALID_METRICS",
]
