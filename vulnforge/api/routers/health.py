"""健康检查路由。"""

from __future__ import annotations


def register(app) -> None:
    from fastapi import APIRouter

    router = APIRouter(tags=["health"])

    @router.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @router.get("/readyz")
    def readyz():
        ready = True
        for mod in (
            "vulnforge.config",
            "vulnforge.core.engine",
            "vulnforge.scanners.registry",
            "vulnforge.llm",
            "vulnforge.report",
        ):
            try:
                __import__(mod)
            except Exception:
                ready = False
                break
        return {"ready": ready}

    @router.get("/version")
    def version():
        try:
            from vulnforge._version import __version__
        except Exception:
            __version__ = "1.0.0"
        return {"version": __version__, "service": "vulnforge"}

    app.include_router(router)
