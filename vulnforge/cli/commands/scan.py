"""``vulnforge scan``：对路径执行扫描并输出报告。"""

from __future__ import annotations

import dataclasses
import os
from typing import Any, List

from vulnforge.cli import common


def cmd_scan(args) -> int:
    """收集目标 -> 扫描 -> 渲染并写文件 -> 打印统计表。"""
    from vulnforge.config import load_config
    from vulnforge.core.engine import ScanEngine
    from vulnforge.core.target import TargetCollector
    from vulnforge.report import render, write

    cfg = load_config(getattr(args, "config", None))
    if getattr(args, "no_llm", False):
        cfg.setdefault("scanners", {})["llm"] = False

    targets = TargetCollector().collect(args.paths, cfg)
    if not targets:
        print(common.colored("未发现可扫描目标。", "yellow"))
        return 0

    report = ScanEngine(cfg).scan(targets)

    findings: List[Any] = list(getattr(report, "findings", []) or [])
    if args.severity:
        findings = common.filter_by_severity(findings, args.severity)
        if dataclasses.is_dataclass(report):
            report = dataclasses.replace(report, findings=findings)

    formats = args.formats or cfg.get("general", {}).get("default_formats") or ["json"]
    out_dir = args.output or cfg.get("general", {}).get("output_dir") or "./results"
    os.makedirs(out_dir, exist_ok=True)

    scan_id = getattr(report, "scan_id", None) or "scan"
    for fmt in formats:
        path = os.path.join(out_dir, f"{scan_id}.{_fmt_ext(fmt)}")
        write(report, fmt, path)
        print(f"已写入: {path}")

    _print_summary(findings)
    return 0


def _fmt_ext(fmt: str) -> str:
    return {
        "markdown": "md",
        "html": "html",
        "sarif": "sarif",
        "json": "json",
        "text": "txt",
    }.get(fmt, fmt)


def _print_summary(findings: List[Any]) -> None:
    rows = []
    for f in findings:
        sev = getattr(f.severity, "value", str(f.severity))
        rows.append([
            sev,
            getattr(f, "rule_id", ""),
            getattr(f, "file_path", ""),
            str(getattr(f, "line", "")),
            getattr(f, "title", ""),
        ])
    print()
    print("扫描统计")
    common.print_table(rows, headers=["severity", "rule_id", "file", "line", "title"])

    counts: dict = {}
    for f in findings:
        sev = getattr(f.severity, "value", "info")
        counts[sev] = counts.get(sev, 0) + 1
    summary = "  ".join(
        f"{k}:{v}"
        for k, v in sorted(counts.items(), key=lambda kv: -common.SEVERITY_RANK.get(kv[0], 0))
    )
    print(f"共 {len(findings)} 个 finding | {summary}")
