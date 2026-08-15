"""vulnforge CLI 入口（纯 argparse，零第三方依赖）。"""

from __future__ import annotations

import argparse
import sys
from typing import Optional


PROG = "vulnforge"
DESCRIPTION = "vulnforge — AI 驱动的自主漏洞挖掘与安全审计平台"


def _get_version() -> str:
    try:
        from vulnforge._version import __version__

        return __version__
    except Exception:
        return "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    """构建命令行解析器。"""
    parser = argparse.ArgumentParser(prog=PROG, description=DESCRIPTION)
    parser.add_argument(
        "--version", action="version", version=_get_version()
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_scan = sub.add_parser("scan", help="对指定路径执行漏洞扫描")
    p_scan.add_argument("paths", nargs="+", metavar="PATH", help="要扫描的文件或目录")
    p_scan.add_argument(
        "--format", dest="formats", action="append",
        choices=["json", "markdown", "html", "sarif", "text"],
        help="输出格式，可多次指定",
    )
    p_scan.add_argument("--config", help="配置文件路径")
    p_scan.add_argument(
        "--severity", default=None,
        choices=["info", "low", "medium", "high", "critical"],
        help="只报告不低于该严重度的 finding",
    )
    p_scan.add_argument("--output", "-o", help="输出目录")
    p_scan.add_argument("--no-llm", action="store_true", help="禁用 LLM 扫描")

    p_serve = sub.add_parser("serve", help="启动 FastAPI 控制面")
    p_serve.add_argument("--host", default=None, help="监听地址")
    p_serve.add_argument("--port", type=int, default=None, help="监听端口")
    p_serve.add_argument("--config", help="配置文件路径")

    p_rules = sub.add_parser("rules", help="列出静态扫描规则")
    p_rules.add_argument("--config", help="配置文件路径")

    p_providers = sub.add_parser("providers", help="列出 LLM provider")
    p_providers.add_argument("--config", help="配置文件路径")

    p_scanners = sub.add_parser("scanners", help="列出可用扫描器")
    p_scanners.add_argument("--config", help="配置文件路径")

    p_fuzz = sub.add_parser("fuzz", help="对目标函数或命令进行 fuzz")
    p_fuzz.add_argument("target", help="命令模板(含 {input})或 module:function")
    p_fuzz.add_argument("--iterations", type=int, default=1000, help="fuzz 迭代次数")
    p_fuzz.add_argument("--timeout", type=float, default=5.0, help="单次执行超时(秒)")
    p_fuzz.add_argument("--config", help="配置文件路径")

    p_sbom = sub.add_parser("sbom", help="生成 SBOM")
    p_sbom.add_argument("paths", nargs="+", metavar="PATH", help="项目目录或清单文件")
    p_sbom.add_argument("--output", "-o", default="sbom.json", help="输出文件")
    p_sbom.add_argument(
        "--ecosystem", default="auto",
        choices=["auto", "pypi", "npm", "maven", "cargo", "go"],
        help="依赖生态",
    )
    p_sbom.add_argument("--config", help="配置文件路径")

    p_report = sub.add_parser("report", help="将已有 JSON 扫描结果转换为其它格式")
    p_report.add_argument("input", help="输入 JSON 结果文件")
    p_report.add_argument(
        "--format", dest="formats", action="append",
        choices=["json", "markdown", "html", "sarif", "text"],
        help="输出格式，可多次指定",
    )
    p_report.add_argument("--output", "-o", help="输出文件")
    p_report.add_argument("--config", help="配置文件路径")

    sub.add_parser("doctor", help="自检环境与依赖")
    sub.add_parser("version", help="打印版本号")

    return parser


_COMMAND_FUNCS = {
    "scan": "cmd_scan",
    "serve": "cmd_serve",
    "rules": "cmd_rules",
    "providers": "cmd_providers",
    "scanners": "cmd_scanners",
    "fuzz": "cmd_fuzz",
    "sbom": "cmd_sbom",
    "report": "cmd_report",
    "doctor": "cmd_doctor",
}


def main(argv: Optional[list] = None) -> int:
    """CLI 入口，返回进程退出码。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "version":
        print(_get_version())
        return 0

    import importlib

    module = importlib.import_module(f"vulnforge.cli.commands.{args.command}")
    func = getattr(module, _COMMAND_FUNCS[args.command])

    try:
        return int(func(args) or 0)
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI 顶层兜底
        print(f"错误: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
