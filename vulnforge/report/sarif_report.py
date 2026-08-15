"""SARIF 2.1.0 report renderer.

Produces a SARIF document suitable for direct upload to GitHub Code Scanning.
Each finding becomes a ``result`` with ``ruleId``, ``level``, ``message`` and a
``physicalLocation``.
"""

import json
from typing import Any, Dict, List

from .summary import severity_name

_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def render(report) -> str:
    """Render ``report`` as a SARIF 2.1.0 JSON string."""
    findings = list(getattr(report, "findings", []) or [])

    # Collect unique rules for the tool.driver.rules section.
    rules: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        rule_id = getattr(f, "rule_id", "") or "generic"
        if rule_id not in rules:
            rules[rule_id] = _rule(f)

    results = [_result(f) for f in findings]

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnforge",
                        "informationUri": "https://github.com/huzjie/vulnforge",
                        "semanticVersion": _tool_version(report),
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2, default=str)


def _tool_version(report) -> str:
    for attr in ("version", "tool_version"):
        value = getattr(report, attr, None)
        if value:
            return str(value)
    return "1.0.0"


def _rule(f) -> Dict[str, Any]:
    rule_id = getattr(f, "rule_id", "") or "generic"
    rule = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": getattr(f, "title", "") or rule_id},
        "fullDescription": {"text": getattr(f, "description", "") or ""},
    }
    recommendation = getattr(f, "recommendation", "")
    if recommendation:
        rule["help"] = {"text": recommendation}
    return rule


def _result(f) -> Dict[str, Any]:
    name = severity_name(f)
    rule_id = getattr(f, "rule_id", "") or "generic"
    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": getattr(f, "file_path", "") or ""},
            "region": {
                "startLine": max(1, int(getattr(f, "line", 0) or 1)),
                "startColumn": max(1, int(getattr(f, "column", 0) or 0) + 1),
            },
        }
    }
    message_text = getattr(f, "description", "") or getattr(f, "title", "")

    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": _LEVEL_MAP.get(name, "warning"),
        "message": {"text": message_text},
        "locations": [location],
    }

    partial_fingerprints = {}
    fingerprint = getattr(f, "fingerprint", None)
    if fingerprint:
        partial_fingerprints["primaryLocationLineHash"] = str(fingerprint)
    if partial_fingerprints:
        result["partialFingerprints"] = partial_fingerprints

    return result
