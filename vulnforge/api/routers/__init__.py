"""API 路由集合。

各 router 模块在 :func:`register_routers` 内延迟导入，避免未安装 fastapi 时
触发顶层依赖加载。
"""

from __future__ import annotations

from typing import List

#: 需要注册的 router 模块名（顺序即注册顺序）。
ROUTERS: List[str] = [
    "health",
    "scans",
    "findings",
    "reports",
    "targets",
    "rules",
    "providers",
    "admin",
]


def register_routers(app) -> None:
    """将全部路由注册到应用（延迟导入各模块）。"""
    from vulnforge.api.routers import (
        admin,
        findings,
        health,
        providers,
        reports,
        rules,
        scans,
        targets,
    )

    for module in (health, scans, findings, reports, targets, rules, providers, admin):
        module.register(app)


__all__ = ["ROUTERS", "register_routers"]
