"""LLM provider 路由。"""

from __future__ import annotations


def register(app) -> None:
    from fastapi import APIRouter, Depends

    from vulnforge.api.auth import require_auth

    router = APIRouter(tags=["providers"], dependencies=[Depends(require_auth)])

    @router.get("/providers")
    def list_providers():
        from vulnforge.llm import list_providers as _list

        providers = _list() or []
        out = [p if isinstance(p, str) else (p.get("name") or str(p)) for p in providers]
        return {"total": len(out), "providers": out}

    app.include_router(router)
