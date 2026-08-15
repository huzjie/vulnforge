"""管理路由：统计与配置重载。"""

from __future__ import annotations


def _version() -> str:
    try:
        from vulnforge._version import __version__

        return __version__
    except Exception:
        return "1.0.0"


def register(app) -> None:
    from fastapi import APIRouter, Depends

    from vulnforge.api.auth import require_auth

    router = APIRouter(tags=["admin"], dependencies=[Depends(require_auth)])

    @router.get("/admin/stats")
    def stats():
        scans = app.state.scans
        completed = sum(1 for r in scans.values() if r.get("status") == "completed")
        failed = sum(1 for r in scans.values() if r.get("status") == "failed")
        running = sum(1 for r in scans.values() if r.get("status") == "running")
        total_findings = sum(r.get("findings_count", 0) for r in scans.values())
        return {
            "version": _version(),
            "scans_total": len(scans),
            "scans_completed": completed,
            "scans_failed": failed,
            "scans_running": running,
            "findings_total": total_findings,
        }

    @router.post("/admin/reload")
    def reload_config():
        from vulnforge.config import load_config

        app.state.config = load_config()
        return {"status": "ok", "message": "config reloaded"}

    app.include_router(router)
