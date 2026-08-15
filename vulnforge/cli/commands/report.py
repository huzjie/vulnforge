"""``vulnforge report``：将已有 JSON 扫描结果转换为其它格式。"""

from __future__ import annotations

import json
from typing import Any, Dict, List


_FINDING_FIELDS = {
    "rule_id", "title", "description", "severity", "file_path", "line",
    "column", "code", "cwe", "cvss", "confidence", "scanner",
    "recommendation", "references", "tags", "raw",
}
_TARGET_FIELDS = {"path", "kind", "language", "size"}


def _reconstruct_report(data: Dict[str, Any]):
    """将 JSON dict 还原为 :class:`~vulnforge.models.ScanReport`。"""
    from vulnforge.models import Finding, ScanReport, Severity, Target

    findings: List[Finding] = []
    for item in data.get("findings", []) or []:
        if not isinstance(item, dict):
            continue
        fields = {k: v for k, v in item.items() if k in _FINDING_FIELDS}
        if "severity" in fields and not isinstance(fields["severity"], Severity):
            fields["severity"] = Severity.from_str(str(fields["severity"]))
        findings.append(Finding(**fields))

    targets: List[Target] = []
    for item in data.get("targets", []) or []:
        if not isinstance(item, dict):
            continue
        fields = {k: v for k, v in item.items() if k in _TARGET_FIELDS}
        if "path" not in fields:
            continue
        fields.setdefault("kind", "file")
        fields.setdefault("language", "")
        fields.setdefault("size", 0)
        targets.append(Target(**fields))

    return ScanReport(
        scan_id=data.get("scan_id", "reconstructed"),
        created_at=data.get("created_at", ""),
        targets=targets,
        findings=findings,
        stats=data.get("stats", {}) or {},
        config=data.get("config", {}) or {},
    )


def cmd_report(args) -> int:
    """读取 JSON 结果并渲染/写出目标格式。"""
    from vulnforge.report import render, write

    with open(args.input, encoding="utf-8") as fh:
        data = json.load(fh)

    report = _reconstruct_report(data)
    formats = args.formats or ["markdown"]

    if args.output:
        fmt = formats[0]
        write(report, fmt, args.output)
        print(f"已写入: {args.output}")
    else:
        for fmt in formats:
            print(render(report, fmt))
    return 0
