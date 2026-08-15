"""finding 查询路由。"""

from __future__ import annotations

from typing import Any, Dict, Iterator


def _finding_to_dict(scan_id: str, index: int, f: Any) -> Dict[str, Any]:
    sev = getattr(getattr(f, "severity", None), "value", None) or "info"
    return {
        "id": f"{scan_id}:{index}",
        "rule_id": getattr(f, "rule_id", ""),
        "title": getattr(f, "title", ""),
        "description": getattr(f, "description", ""),
        "severity": sev,
        "file_path": getattr(f, "file_path", ""),
        "line": getattr(f, "line", 0),
        "column": getattr(f, "column", 0),
        "code": getattr(f, "code", ""),
        "cwe": getattr(f, "cwe", ""),
        "cvss": getattr(f, "cvss", None),
        "confidence": getattr(f, "confidence", 1.0),
        "scanner": getattr(f, "scanner", "static"),
        "recommendation": getattr(f, "recommendation", ""),
        "references": list(getattr(f, "references", []) or []),
        "tags": list(getattr(f, "tags", []) or []),
        "raw": dict(getattr(f, "raw", {}) or {}),
    }


def _iter_findings(state, scan_id: str) -> Iterator:
    rec = state.scans.get(scan_id)
    report = rec.get("report") if rec else None
    findings = getattr(report, "findings", []) if report is not None else []
    for index, f in enumerate(findings or []):
        yield index, f


def register(app) -> None:
    from fastapi import APIRouter, Depends, HTTPException, Query

    from vulnforge.api.auth import require_auth

    router = APIRouter(tags=["findings"], dependencies=[Depends(require_auth)])

    @router.get("/findings")
    def list_findings(
        scan_id: str = Query(None),
        severity: str = Query(None),
        file: str = Query(None),
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ):
        items = []
        scan_ids = [scan_id] if scan_id else list(app.state.scans.keys())
        for sid in scan_ids:
            for index, f in _iter_findings(app.state, sid):
                d = _finding_to_dict(sid, index, f)
                if severity and d["severity"] != severity:
                    continue
                if file and file not in d["file_path"]:
                    continue
                items.append(d)
        total = len(items)
        page = items[offset:offset + limit]
        return {"total": total, "items": page, "limit": limit, "offset": offset}

    @router.get("/findings/{fid}")
    def get_finding(fid: str):
        scan_id, _, index = fid.rpartition(":")
        if not scan_id or not index.isdigit():
            raise HTTPException(status_code=404, detail="finding not found")
        for i, f in _iter_findings(app.state, scan_id):
            if i == int(index):
                return _finding_to_dict(scan_id, i, f)
        raise HTTPException(status_code=404, detail="finding not found")

    app.include_router(router)
