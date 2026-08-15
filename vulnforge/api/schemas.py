"""Pydantic 请求/响应模型。"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """发起扫描的请求体。"""

    paths: List[str] = Field(..., min_length=1)
    scanners: Optional[Dict[str, Any]] = None


class FindingOut(BaseModel):
    """单个 finding 的响应模型。"""

    id: str
    rule_id: str
    title: str
    description: str = ""
    severity: str
    file_path: str = ""
    line: int = 0
    column: int = 0
    code: str = ""
    cwe: str = ""
    cvss: Optional[float] = None
    confidence: float = 1.0
    scanner: str = "static"
    recommendation: str = ""
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)


class ScanResponse(BaseModel):
    """发起扫描后的响应模型。"""

    scan_id: str
    status: str
    findings_count: int = 0
    report: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class ErrorOut(BaseModel):
    """通用错误响应模型。"""

    detail: str


__all__ = ["ScanRequest", "FindingOut", "ScanResponse", "ErrorOut"]
