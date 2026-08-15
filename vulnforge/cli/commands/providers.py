"""``vulnforge providers``：列出 LLM provider。"""

from __future__ import annotations

from vulnforge.cli import common


def cmd_providers(args) -> int:
    """列出可用的 LLM provider 名称。"""
    from vulnforge.llm import list_providers

    providers = list_providers() or []
    if not providers:
        print(common.colored("未发现 LLM provider。", "yellow"))
        return 0
    common.print_table([[p] for p in providers], headers=["provider"])
    print(f"共 {len(providers)} 个 provider")
    return 0
