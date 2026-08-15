"""``vulnforge fuzz``：轻量级 fuzz（命令模板或 Python 函数）。

用法示例::

    vulnforge fuzz "python -c 'print({input})'"
    vulnforge fuzz mymodule:myfunc --iterations 500

目标可以是包含 ``{input}`` 占位符的命令模板，也可以是 ``module:function``
形式的 Python 可调用对象。崩溃（非零退出/异常）会被记录并汇总。
"""

from __future__ import annotations

import importlib
import random
import shlex
import string
import subprocess
import sys
from typing import Any, Callable, Optional


def _gen_input() -> str:
    """生成多样化的随机输入。"""
    choice = random.randint(0, 5)
    if choice == 0:
        return ""
    if choice == 1:
        return "A" * random.randint(1, 512)
    if choice == 2:
        return "%s%n%d" * random.randint(1, 16)
    if choice == 3:
        return "".join(
            random.choice(string.printable) for _ in range(random.randint(1, 256))
        )
    if choice == 4:
        return "".join(
            random.choice("\x00\xff\n\r\t") for _ in range(random.randint(1, 64))
        )
    return "".join(
        random.choice(string.ascii_letters + string.digits)
        for _ in range(random.randint(1, 128))
    )


def _run_command(template: str, data: str, timeout: float) -> Optional[str]:
    """执行命令模板；返回 ``"hang"``/``"crash"`` 或 ``None``。"""
    if "{input}" in template:
        cmd = template.replace("{input}", shlex.quote(data))
        stdin = None
    else:
        cmd = template
        stdin = data.encode("utf-8", "replace")
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            input=stdin,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return "hang"
    if proc.returncode < 0:  # 被信号终止
        return "crash"
    return None


def _run_python_func(spec: str, data: str, timeout: float) -> Optional[str]:
    """调用 Python 函数；异常视为崩溃。"""
    del timeout  # 函数调用无法跨平台强制中断，仅用于签名一致
    module_name, _, func_name = spec.partition(":")
    if not module_name or not func_name:
        return "invalid-spec"
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        return f"import-error: {exc}"
    func: Any = getattr(module, func_name, None)
    if not callable(func):
        return "not-callable"
    try:
        func(data)
    except Exception:
        return "crash"
    return None


def cmd_fuzz(args) -> int:
    """运行 fuzz 循环并打印汇总。"""
    target: str = args.target
    iterations = max(1, int(args.iterations))
    timeout = max(0.01, float(args.timeout))

    if ":" in target and not target.lstrip().startswith(("http:", "https:")):
        runner: Callable[..., Optional[str]] = _run_python_func
    else:
        runner = _run_command

    crashes = 0
    hangs = 0
    other: dict = {}
    print(f"fuzz 目标: {target} | 迭代: {iterations} | 超时: {timeout}s")

    for i in range(iterations):
        data = _gen_input()
        result = runner(target, data, timeout)
        if result == "crash":
            crashes += 1
            print(f"[{i}] crash  input={data!r}")
            if crashes >= 20:
                print("崩溃数量达到上限，提前结束。")
                break
        elif result == "hang":
            hangs += 1
        elif result:
            other[result] = other.get(result, 0) + 1

    print("-" * 40)
    print(f"总迭代: {iterations}")
    print(f"崩溃: {crashes} | 超时: {hangs}")
    if other:
        print("其它: " + "  ".join(f"{k}:{v}" for k, v in other.items()))
    return 0 if crashes == 0 else 1
