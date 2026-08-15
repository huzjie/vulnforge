"""vulnforge Python SDK 客户端（仅依赖标准库 urllib）。"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib import error, parse, request

from vulnforge_sdk.exceptions import VulnforgeAPIError
from vulnforge_sdk.models import ScanResponse


class VulnforgeClient:
    """与 vulnforge API 控制面交互的轻量客户端。"""

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def __enter__(self) -> "VulnforgeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    # ------------------------------------------------------------------
    # 底层请求
    # ------------------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        body: Any = None,
    ) -> Any:
        url = self.base_url + path
        if params:
            qs = parse.urlencode(
                [(k, v) for k, v in params.items() if v is not None]
            )
            if qs:
                url += "?" + qs

        data = None
        headers: Dict[str, str] = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                ctype = resp.headers.get("Content-Type", "")
                if "json" in ctype:
                    return json.loads(raw) if raw else None
                return raw
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise VulnforgeAPIError(
                f"HTTP {exc.code}: {detail}", status_code=exc.code, body=detail
            ) from exc
        except error.URLError as exc:
            raise VulnforgeAPIError(str(exc.reason)) from exc

    # ------------------------------------------------------------------
    # 业务方法
    # ------------------------------------------------------------------
    def health(self) -> Dict[str, Any]:
        """GET /healthz。"""
        return self._request("GET", "/healthz")

    def version(self) -> Dict[str, Any]:
        """GET /version。"""
        return self._request("GET", "/version")

    def scan(
        self,
        paths: List[str],
        scanners: Optional[Dict[str, Any]] = None,
    ) -> ScanResponse:
        """POST /scan，返回 ScanResponse。"""
        payload: Dict[str, Any] = {"paths": list(paths)}
        if scanners:
            payload["scanners"] = scanners
        data = self._request("POST", "/scan", body=payload)
        return ScanResponse.from_dict(data)

    def get_scan(self, scan_id: str) -> ScanResponse:
        """GET /scan/{scan_id}。"""
        data = self._request("GET", f"/scan/{scan_id}")
        return ScanResponse.from_dict(data)

    def list_scans(self) -> List[Dict[str, Any]]:
        """GET /scans。"""
        data = self._request("GET", "/scans")
        if isinstance(data, dict):
            return data.get("scans", [])
        return data or []

    def findings(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        file: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """GET /findings（支持过滤与分页）。"""
        params = {
            "scan_id": scan_id,
            "severity": severity,
            "file": file,
            "limit": limit,
            "offset": offset,
        }
        return self._request("GET", "/findings", params=params)

    def reports(self, scan_id: str, fmt: str = "json") -> str:
        """GET /reports/{scan_id}?format=...，返回渲染后的文本。"""
        return self._request("GET", f"/reports/{scan_id}", params={"format": fmt})

    def rules(self) -> Dict[str, Any]:
        """GET /rules。"""
        return self._request("GET", "/rules")

    def scanners(self) -> Dict[str, Any]:
        """GET /scanners。"""
        return self._request("GET", "/scanners")

    def providers(self) -> Dict[str, Any]:
        """GET /providers。"""
        return self._request("GET", "/providers")


__all__ = ["VulnforgeClient"]
