"""``vulnforge doctor``：自检版本/依赖/配置/模块/规则/provider。"""

from __future__ import annotations

from vulnforge.cli import common


def _version() -> str:
    try:
        from vulnforge._version import __version__

        return __version__
    except Exception:
        return "1.0.0"


def cmd_doctor(args) -> int:
    """执行一系列自检并输出报告表。"""
    checks: list = []

    checks.append(("版本", _version(), True))

    for mod in ("fastapi", "uvicorn", "yaml", "httpx"):
        try:
            __import__(mod)
            checks.append((f"依赖 {mod}", "已安装", True))
        except Exception:
            checks.append((f"依赖 {mod}", "未安装(可选)", True))

    try:
        from vulnforge.config import load_config

        load_config()
        checks.append(("配置加载", "ok", True))
    except Exception as exc:
        checks.append(("配置加载", str(exc), False))

    for mod in (
        "vulnforge.models",
        "vulnforge.core.engine",
        "vulnforge.core.target",
        "vulnforge.scanners.registry",
        "vulnforge.llm",
        "vulnforge.report",
        "vulnforge.errors",
    ):
        try:
            __import__(mod)
            checks.append((f"模块 {mod}", "ok", True))
        except Exception as exc:
            checks.append((f"模块 {mod}", str(exc), False))

    try:
        n = sum(1 for _ in common.iter_static_rules())
        checks.append(("静态规则数", str(n), True))
    except Exception as exc:
        checks.append(("静态规则数", str(exc), False))

    try:
        from vulnforge.llm import list_providers

        n = len(list_providers() or [])
        checks.append(("LLM provider 数", str(n), True))
    except Exception as exc:
        checks.append(("LLM provider 数", str(exc), False))

    rows = [[name, val, "ok" if ok else "FAIL"] for (name, val, ok) in checks]
    common.print_table(rows, headers=["检查项", "结果", "状态"])
    failed = sum(1 for _, _, ok in checks if not ok)
    if failed:
        print(common.colored(f"{failed} 项未通过", "red"))
        return 1
    print(common.colored("全部通过", "green"))
    return 0
