"""vulnforge FastAPI 控制面。

fastapi / uvicorn 为可选依赖，仅在调用 :func:`create_app` 时才延迟导入，
确保未安装时内核仍可正常 import。
"""

from __future__ import annotations

from typing import Any, Optional


def create_app(config: Optional[dict] = None):
    """创建 FastAPI 应用（延迟导入 fastapi 与各 router）。"""
    from vulnforge.api.app import create_app as _create_app

    return _create_app(config)


__all__ = ["create_app"]
