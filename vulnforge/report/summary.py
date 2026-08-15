"""Scan report summarization helpers.

Produces a machine-friendly summary dictionary: per-severity counts, top rules,
top files, top CWEs and prioritized remediation suggestions.
"""

from collections import Counter
from typing import Any, Dict, List

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_PRIORITY_ACTIONS = {
    "CRITICAL": ("P0", "立即修复，可导致远程代码执行 / 数据完全泄露"),
    "HIGH": ("P1", "尽快修复，存在被利用的高风险"),
    "MEDIUM": ("P2", "按计划修复，需结合上下文评估利用难度"),
    "LOW": ("P3", "低优先级，建议在迭代中顺手修复"),
    "INFO": ("P4", "提示信息，无需立即处理"),
}


def severity_name(finding) -> str:
    """Return the canonical severity name of a finding (e.g. ``"HIGH"``)."""
    sev = getattr(finding, "severity", None)
    name = getattr(sev, "name", None)
    return name or str(sev) or "INFO"


def _serialize_finding(finding) -> Dict[str, Any]:
    """Convert a Finding into a plain dict for embedding in summaries/JSON."""
    refs = getattr(finding, "references", None) or []
    tags = getattr(finding, "tags", None) or []
    raw = getattr(finding, "raw", None) or {}
    return {
        "rule_id": getattr(finding, "rule_id", ""),
        "title": getattr(finding, "title", ""),
        "description": getattr(finding, "description", ""),
        "severity": severity_name(finding),
        "file_path": getattr(finding, "file_path", ""),
        "line": getattr(finding, "line", 0),
        "column": getattr(finding, "column", 0),
        "code": getattr(finding, "code", ""),
        "cwe": getattr(finding, "cwe", "") or "",
        "cvss": getattr(finding, "cvss", None),
        "confidence": getattr(finding, "confidence", 1.0),
        "scanner": getattr(finding, "scanner", ""),
        "recommendation": getattr(finding, "recommendation", ""),
        "references": list(refs),
        "tags": list(tags),
        "raw": raw if isinstance(raw, dict) else {},
    }


def summarize(report) -> Dict[str, Any]:
    """Return a summary dictionary for a :class:`ScanReport`."""
    findings: List[Any] = list(getattr(report, "findings", []) or [])

    counts = {name: 0 for name in SEVERITY_ORDER}
    for f in findings:
        name = severity_name(f)
        if name in counts:
            counts[name] += 1

    rule_counter = Counter(getattr(f, "rule_id", "") for f in findings)
    file_counter = Counter(getattr(f, "file_path", "") for f in findings)
    cwe_counter = Counter((getattr(f, "cwe", "") or "") for f in findings)
    scanner_counter = Counter(getattr(f, "scanner", "") for f in findings)

    top_rules = [{"rule_id": r, "count": c} for r, c in rule_counter.most_common(10)]
    top_files = [{"file": p, "count": c} for p, c in file_counter.most_common(10)]
    top_cwe = [{"cwe": c, "count": n} for c, n in cwe_counter.most_common(10) if c]
    by_scanner = [{"scanner": s, "count": c} for s, c in scanner_counter.most_common()]

    priority: List[Dict[str, Any]] = []
    for sev in SEVERITY_ORDER:
        if counts.get(sev, 0) <= 0:
            continue
        level, action = _PRIORITY_ACTIONS[sev]
        priority.append({
            "level": level,
            "severity": sev,
            "count": counts[sev],
            "action": action,
        })

    return {
        "total": len(findings),
        "severity_counts": counts,
        "top_rules": top_rules,
        "top_files": top_files,
        "top_cwe": top_cwe,
        "by_scanner": by_scanner,
        "remediation_priority": priority,
    }
