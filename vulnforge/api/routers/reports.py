"""报告渲染路由。"""

from __future__ import annotations


def register(app) -> None:
    from fastapi import APIRouter, Depends, HTTPException
    from fastapi.responses import HTMLResponse, Response

    from vulnforge.api.auth import require_auth

    router = APIRouter(tags=["reports"], dependencies=[Depends(require_auth)])

    _FMT_MEDIA = {
        "json": "application/json",
        "markdown": "text/markdown",
        "html": "text/html",
        "sarif": "application/json",
        "text": "text/plain",
    }

    @router.get("/reports/{scan_id}")
    def get_report(scan_id: str, format: str = "json"):
        if format not in _FMT_MEDIA:
            raise HTTPException(status_code=400, detail=f"unsupported format: {format}")
        rec = app.state.scans.get(scan_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="scan not found")
        report = rec.get("report")
        if report is None:
            raise HTTPException(status_code=404, detail="report not ready")

        from vulnforge.report import render

        text = render(report, format)
        if format == "html":
            return HTMLResponse(content=text)
        return Response(content=text, media_type=_FMT_MEDIA[format])

    app.include_router(router)
