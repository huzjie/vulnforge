"""``vulnforge rules``：列出静态扫描规则。"""

from __future__ import annotations

from vulnforge.cli import common


def _sev(severity) -> str:
    return getattr(severity, "value", str(severity or ""))


def cmd_rules(args) -> int:
    """列出静态规则的 id/title/severity/cwe。"""
    rows = []
    for rule in common.iter_static_rules():
        rows.append([
            getattr(rule, "id", getattr(rule, "rule_id", "")),
            getattr(rule, "title", ""),
            _sev(getattr(rule, "severity", None)),
            getattr(rule, "cwe", ""),
        ])
    if not rows:
        print(common.colored("未发现静态规则。", "yellow"))
        return 0
    common.print_table(rows, headers=["rule_id", "title", "severity", "cwe"])
    print(f"共 {len(rows)} 条规则")
    return 0
