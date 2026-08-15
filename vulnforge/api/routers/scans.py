"""扫描相关路由。"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

# 请求/响应模型必须位于模块全局命名空间，FastAPI 才能解析路由处理函数的
# 类型注解（嵌套函数注解只能从 __globals__ 解析）。本模块仅在 create_app 内
# （fastapi 已就绪）被导入，故此处延迟导入的约束不变。
from vulnforge.api.schemas import ScanRequest, ScanResponse  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_scan(state, config: Dict[str, Any], scan_id: str, paths: List[str]) -> None:
    """后台线程：执行扫描并写入内存存储。"""
    try:
        from vulnforge.core.engine import ScanEngine
        from vulnforge.core.target import TargetCollector

        targets = TargetCollector().collect(paths, config)
        report = ScanEngine(config).scan(targets)
        findings = getattr(report, "findings", []) or []
        state.scans[scan_id].update(
            status="completed",
            report=report,
            findings_count=len(findings),
            finished_at=_now(),
        )
    except Exception as exc:  # noqa: BLE001 - 记录失败原因
        state.scans[scan_id].update(
            status="failed", error=str(exc), finished_at=_now()
        )


def register(app) -> None:
    from fastapi import APIRouter, Depends, HTTPException

    from vulnforge.api.auth import require_auth

    router = APIRouter(tags=["scans"], dependencies=[Depends(require_auth)])

    @router.post("/scan", response_model=ScanResponse)
    def create_scan(payload: ScanRequest):
        scan_id = uuid.uuid4().hex
        app.state.scans[scan_id] = {
            "scan_id": scan_id,
            "status": "running",
            "findings_count": 0,
            "report": None,
            "error": None,
            "started_at": _now(),
            "finished_at": None,
            "paths": list(payload.paths),
        }
        thread = threading.Thread(
            target=_run_scan,
            args=(app.state, app.state.config, scan_id, list(payload.paths)),
            daemon=True,
        )
        thread.start()
        return ScanResponse(scan_id=scan_id, status="running", findings_count=0)

    @router.get("/scans")
    def list_scans():
        rows = []
        for scan_id, rec in app.state.scans.items():
            rows.append({
                "scan_id": scan_id,
                "status": rec.get("status"),
                "findings_count": rec.get("findings_count", 0),
                "started_at": rec.get("started_at"),
                "finished_at": rec.get("finished_at"),
                "error": rec.get("error"),
            })
        return {"total": len(rows), "scans": rows}

    @router.get("/scan/{scan_id}")
    def get_scan(scan_id: str):
        rec = app.state.scans.get(scan_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return {
            "scan_id": scan_id,
            "status": rec.get("status"),
            "findings_count": rec.get("findings_count", 0),
            "started_at": rec.get("started_at"),
            "finished_at": rec.get("finished_at"),
            "error": rec.get("error"),
            "paths": rec.get("paths", []),
        }

    app.include_router(router)
