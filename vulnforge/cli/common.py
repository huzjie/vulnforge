"""CLI 共享工具：配置加载、表格打印、颜色输出、规则枚举。"""

from __future__ import annotations

import os
import sys
from typing import Any, Iterator, List, Optional, Sequence

# 严重度排序（用于阈值过滤与展示）。
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def load_config(path: Optional[str] = None) -> dict:
    """加载配置（延迟导入内核 config 模块）。"""
    from vulnforge.config import load_config as _load

    return _load(path)


def colored(text: str, color: Optional[str] = None) -> str:
    """返回带 ANSI 颜色的文本；非 TTY 或设置了 NO_COLOR 时原样返回。"""
    if not color or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    codes = {
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "white": "37",
        "bold": "1",
    }
    return f"\033[{codes.get(color, '0')}m{text}\033[0m"


def severity_color(severity: str) -> str:
    """返回严重度对应的显示颜色。"""
    return {
        "critical": "red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "white",
    }.get(severity, "white")


def _display_width(text: str) -> int:
    """近似显示宽度（CJK 字符按 2 列计）。"""
    return sum(2 if ord(ch) > 0x2E7F else 1 for ch in text)


def print_table(
    rows: Sequence[Sequence[Any]],
    headers: Optional[Sequence[str]] = None,
) -> None:
    """打印对齐的文本表格。"""
    if not rows and not headers:
        return
    table: List[List[str]] = []
    if headers:
        table.append([str(h) for h in headers])
    table.extend([[str(c) for c in row] for row in rows])

    ncols = max(len(r) for r in table)
    widths = [0] * ncols
    for row in table:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], _display_width(cell))

    for idx, row in enumerate(table):
        cells: List[str] = []
        for i in range(ncols):
            cell = row[i] if i < len(row) else ""
            cells.append(cell + " " * max(0, widths[i] - _display_width(cell)))
        print("  ".join(cells).rstrip())
        if headers and idx == 0:
            print("  ".join("-" * w for w in widths))


def filter_by_severity(findings: List[Any], threshold: Optional[str]) -> List[Any]:
    """按最低严重度阈值过滤 findings（返回新列表）。"""
    if not threshold:
        return list(findings)
    try:
        from vulnforge.models import Severity

        cutoff = Severity.from_str(threshold)
        return [f for f in findings if f.severity >= cutoff]
    except Exception:  # 内核不可用时退回字符串排序
        rank = SEVERITY_RANK.get(threshold, 0)

        def _rank(f: Any) -> int:
            sev = getattr(getattr(f, "severity", None), "value", None)
            return SEVERITY_RANK.get(sev, 0)

        return [f for f in findings if _rank(f) >= rank]


def iter_static_rules() -> Iterator:
    """枚举静态扫描规则（依赖内核 scanner registry）。"""
    try:
        from vulnforge.scanners.registry import all_scanners

        for scanner in all_scanners():
            if getattr(scanner, "name", "") == "static":
                rules = getattr(scanner, "rules", None)
                if isinstance(rules, (list, tuple)):
                    return iter(rules)
    except Exception:
        pass
    return iter(())
