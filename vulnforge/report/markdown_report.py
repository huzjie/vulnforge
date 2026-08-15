"""Markdown report renderer.

Produces a human-readable Markdown document: an overview statistics table,
per-severity grouped finding lists, and remediation suggestions.
"""

from typing import Any, List

from .summary import SEVERITY_ORDER, severity_name, summarize


def _group_by_severity(findings: List[Any]) -> dict:
    groups = {name: [] for name in SEVERITY_ORDER}
    for f in findings:
        name = severity_name(f)
        groups.setdefault(name, []).append(f)
    return groups


def render(report) -> str:
    """Render ``report`` as a Markdown string."""
    findings = list(getattr(report, "findings", []) or [])
    stats = summarize(report)
    counts = stats["severity_counts"]

    lines: List[str] = []
    lines.append("# vulnforge 安全扫描报告")
    lines.append("")
    lines.append(f"共发现 **{stats['total']}** 个问题。")
    lines.append("")

    # Overview table.
    lines.append("## 概览")
    lines.append("")
    lines.append("| 严重度 | 数量 |")
    lines.append("| --- | --- |")
    for name in SEVERITY_ORDER:
        lines.append(f"| {name} | {counts.get(name, 0)} |")
    lines.append("")

    # Remediation priority.
    priority = stats.get("remediation_priority", [])
    if priority:
        lines.append("## 修复优先级建议")
        lines.append("")
        for item in priority:
            lines.append(
                f"- **{item['level']}** [{item['severity']}] {item['count']} 个：{item['action']}"
            )
        lines.append("")

    # Top rules / files / CWE.
    if stats.get("top_rules"):
        lines.append("## Top 规则")
        lines.append("")
        for entry in stats["top_rules"][:10]:
            lines.append(f"- `{entry['rule_id']}` — {entry['count']} 次")
        lines.append("")
    if stats.get("top_files"):
        lines.append("## Top 文件")
        lines.append("")
        for entry in stats["top_files"][:10]:
            lines.append(f"- `{entry['file']}` — {entry['count']} 次")
        lines.append("")

    # Grouped findings.
    groups = _group_by_severity(findings)
    lines.append("## 漏洞详情")
    lines.append("")
    for name in SEVERITY_ORDER:
        group = groups.get(name, [])
        if not group:
            continue
        lines.append(f"### {name}（{len(group)}）")
        lines.append("")
        for f in group:
            lines.append(_render_finding(f))
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_finding(f) -> str:
    title = f"**{getattr(f, 'rule_id', '')}** — {getattr(f, 'title', '')}"
    location = f"{getattr(f, 'file_path', '')}:{getattr(f, 'line', 0)}"
    cwe = getattr(f, "cwe", "") or ""
    cvss = getattr(f, "cvss", None) or ""
    scanner = getattr(f, "scanner", "")

    parts = [f"- {title}"]
    parts.append(f"  - 位置：`{location}`")
    if cwe:
        parts.append(f"  - CWE：{cwe}")
    if cvss:
        parts.append(f"  - CVSS：`{cvss}`")
    if scanner:
        parts.append(f"  - 扫描器：{scanner}")

    description = getattr(f, "description", "")
    if description:
        parts.append(f"  - 描述：{description}")

    code = getattr(f, "code", "")
    if code:
        parts.append("  - 代码：")
        for code_line in code.splitlines():
            parts.append(f"    ```\n    {code_line}\n    ```")

    recommendation = getattr(f, "recommendation", "")
    if recommendation:
        parts.append(f"  - 建议：{recommendation}")

    return "\n".join(parts)
