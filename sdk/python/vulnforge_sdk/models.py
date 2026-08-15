"""vulnforge Python SDK 数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """单个漏洞或可疑代码发现。"""

    rule_id: str
    title: str
    description: str = ""
    severity: str = "info"
    file_path: str = ""
    line: int = 0
    column: int = 0
    code: str = ""
    cwe: str = ""
    cvss: Optional[float] = None
    confidence: float = 1.0
    scanner: str = "static"
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """从字典构造（忽略未知字段）。"""
        fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**fields)


@dataclass
class ScanResponse:
    """发起扫描后的响应。"""

    scan_id: str
    status: str
    findings_count: int = 0
    report: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResponse":
        """从字典构造（忽略未知字段）。"""
        fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**fields)


__all__ = ["Finding", "ScanResponse"]
