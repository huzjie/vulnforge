"""FastAPI 应用工厂。fastapi/uvicorn 全部延迟导入。"""

from __future__ import annotations

import threading
from typing import Any, Optional


def _load_version() -> str:
    try:
        from vulnforge._version import __version__

        return __version__
    except Exception:
        return "1.0.0"


def create_app(config: Optional[dict] = None):
    """创建并返回 FastAPI 应用实例。

    参数
    ----
    config : dict, optional
        配置字典；为 ``None`` 时调用 :func:`vulnforge.config.load_config`。
    """
    import fastapi
    from fastapi.middleware.cors import CORSMiddleware

    if config is None:
        from vulnforge.config import load_config

        config = load_config()

    app = fastapi.FastAPI(
        title="vulnforge",
        description="AI 驱动的自主漏洞挖掘与安全审计平台 — 控制面",
        version=_load_version(),
    )

    api_cfg = config.get("api", {}) if isinstance(config, dict) else {}
    origins = api_cfg.get("cors_origins", ["*"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.config = config
    app.state.scans = {}
    app.state.scans_lock = threading.Lock()

    @app.get("/", tags=["meta"])
    def root():
        return {
            "service": "vulnforge",
            "version": _load_version(),
            "docs": "/docs",
            "redoc": "/redoc",
            "health": "/healthz",
        }

    @app.on_event("startup")
    def _startup() -> None:
        print(f"vulnforge v{_load_version()} 控制面已启动")

    from vulnforge.api.routers import register_routers

    register_routers(app)
    return app


__all__ = ["create_app"]
