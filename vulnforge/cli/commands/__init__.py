"""CLI 子命令实现。

每个模块暴露 ``cmd_<name>(args)`` 函数，由 :mod:`vulnforge.cli.main` 按需
延迟导入。此包本身不导入任何子模块，以避免在 CLI 未被使用时引入内核依赖。
"""

__all__ = [
    "scan",
    "serve",
    "rules",
    "providers",
    "scanners",
    "doctor",
    "fuzz",
    "sbom",
    "report",
]
