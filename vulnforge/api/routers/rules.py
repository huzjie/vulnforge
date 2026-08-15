"""规则与扫描器路由。"""

from __future__ import annotations


def _sev(severity) -> str:
    return getattr(severity, "value", str(severity or ""))


def register(app) -> None:
    from fastapi import APIRouter, Depends

    from vulnforge.api.auth import require_auth
    from vulnforge.cli.common import iter_static_rules

    router = APIRouter(tags=["rules"], dependencies=[Depends(require_auth)])

    @router.get("/rules")
    def list_rules():
        rules = []
        for rule in iter_static_rules():
            rules.append({
                "rule_id": getattr(rule, "id", getattr(rule, "rule_id", "")),
                "title": getattr(rule, "title", ""),
                "severity": _sev(getattr(rule, "severity", None)),
                "cwe": getattr(rule, "cwe", ""),
            })
        return {"total": len(rules), "rules": rules}

    @router.get("/scanners")
    def list_scanners():
        from vulnforge.scanners.registry import all_scanners, list_scanners as _names

        scanners = []
        instances = all_scanners() or []
        for s in instances:
            desc = getattr(s, "description", "") or ""
            if not desc:
                doc = getattr(s, "__doc__", "") or ""
                desc = doc.strip().splitlines()[0] if doc.strip() else ""
            scanners.append({"name": getattr(s, "name", str(s)), "description": desc})
        if not scanners:
            scanners = [{"name": n, "description": ""} for n in (_names() or [])]
        return {"total": len(scanners), "scanners": scanners}

    app.include_router(router)
