"""Structured JSON report renderer.

Produces a single JSON document containing scan metadata, summary statistics and
the full, normalized list of findings.
"""

import json
from typing import Any, Dict

from .summary import _serialize_finding, summarize


def _meta(report) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    for attr in ("scan_id", "created_at", "targets", "stats", "config"):
        value = getattr(report, attr, None)
        if value is not None:
            meta[attr] = value
    return meta


def render(report) -> str:
    """Render ``report`` as an indented JSON string."""
    findings = list(getattr(report, "findings", []) or [])
    document = {
        "meta": _meta(report),
        "stats": summarize(report),
        "findings": [_serialize_finding(f) for f in findings],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, default=str)
