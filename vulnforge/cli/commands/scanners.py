"""``vulnforge scanners``：列出可用扫描器。"""

from __future__ import annotations

from vulnforge.cli import common


def cmd_scanners(args) -> int:
    """列出已注册的扫描器名称。"""
    from vulnforge.scanners.registry import all_scanners, list_scanners

    scanners = all_scanners() or []
    if not scanners:
        names = list_scanners() or []
        if not names:
            print(common.colored("未发现扫描器。", "yellow"))
            return 0
        common.print_table([[n] for n in names], headers=["scanner"])
        print(f"共 {len(names)} 个扫描器")
        return 0

    rows = []
    for s in scanners:
        name = getattr(s, "name", str(s))
        desc = getattr(s, "description", "") or ""
        if not desc:
            doc = getattr(s, "__doc__", "") or ""
            desc = doc.strip().splitlines()[0] if doc.strip() else ""
        rows.append([name, desc])
    common.print_table(rows, headers=["scanner", "description"])
    print(f"共 {len(rows)} 个扫描器")
    return 0
