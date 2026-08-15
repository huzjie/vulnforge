"""Bearer token 鉴权依赖。"""

from __future__ import annotations

import hmac
from typing import Optional

# Request 仅在 fastapi 可用时才需要；缺失时置 None 以保持本模块可被
# 无 fastapi 环境安全 import（require_auth 只在 fastapi 上下文中被调用）。
try:  # pragma: no cover - fastapi 为可选依赖
    from fastapi import Request  # noqa: F401
except ImportError:  # pragma: no cover
    Request = None  # type: ignore[assignment]


def _token_from_header(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def require_auth(request: "Request") -> bool:
    """FastAPI 依赖：校验 Bearer token。

    ``config["api"]["auth_token"]`` 为空时放行；否则要求请求携带
    ``Authorization: Bearer <token>`` 且与配置一致。
    """
    from fastapi import HTTPException

    config = getattr(request.app.state, "config", {}) or {}
    auth_token = (config.get("api") or {}).get("auth_token", "")
    if not auth_token:
        return True

    token = _token_from_header(request.headers.get("Authorization"))
    if token and hmac.compare_digest(token, auth_token):
        return True

    raise HTTPException(status_code=401, detail="invalid or missing bearer token")


__all__ = ["require_auth"]
