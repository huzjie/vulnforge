"""目标收集路由。"""

from __future__ import annotations

from vulnforge.api.schemas import ScanRequest


def _target_to_dict(t) -> dict:
    return {
        "path": getattr(t, "path", str(t)),
        "kind": getattr(t, "kind", "file"),
        "language": getattr(t, "language", ""),
        "size": getattr(t, "size", 0),
    }


def register(app) -> None:
    from fastapi import APIRouter, Depends

    from vulnforge.api.auth import require_auth

    router = APIRouter(tags=["targets"], dependencies=[Depends(require_auth)])

    @router.post("/targets")
    def collect_targets(payload: ScanRequest):
        from vulnforge.core.target import TargetCollector

        targets = TargetCollector().collect(payload.paths, app.state.config)
        return {"total": len(targets), "targets": [_target_to_dict(t) for t in targets]}

    app.include_router(router)
