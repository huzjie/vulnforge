"""GitHub webhook 工具：HMAC 签名校验与事件解析。

仅依赖标准库，供 webhook 接收端使用。
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, Optional


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """校验 GitHub webhook 的 HMAC-SHA256 签名。

    参数
    ----
    payload : bytes
        原始请求体（未解码字节）。
    signature : str
        ``X-Hub-Signature-256`` 头，形如 ``sha256=...``。
    secret : str
        webhook 配置的共享密钥。

    返回
    ----
    bool
        签名有效返回 ``True``，否则 ``False``。
    """
    if not secret or not signature:
        return False
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    expected = "sha256=" + digest
    return hmac.compare_digest(expected, signature)


def parse_github_event(event: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """从 GitHub webhook 事件提取仓库、分支、提交等关键信息。

    支持 ``pull_request`` 与 ``push`` 事件；无法识别时返回 ``None``。
    """
    if not event or not isinstance(payload, dict):
        return None

    repo = (payload.get("repository") or {}).get("full_name")

    if event == "pull_request":
        pr = payload.get("pull_request") or {}
        head = pr.get("head") or {}
        base = pr.get("base") or {}
        return {
            "event": "pull_request",
            "repo": repo,
            "action": payload.get("action"),
            "number": payload.get("number") or pr.get("number"),
            "branch": head.get("ref"),
            "base_branch": base.get("ref"),
            "commit": head.get("sha"),
            "head_sha": head.get("sha"),
            "title": pr.get("title"),
        }

    if event == "push":
        ref = payload.get("ref") or ""
        branch = ref.split("/", 2)[-1] if ref.startswith("refs/heads/") else ref
        return {
            "event": "push",
            "repo": repo,
            "branch": branch,
            "ref": ref,
            "commit": payload.get("after"),
            "head_sha": payload.get("after"),
            "commits": payload.get("commits") or [],
        }

    return None


__all__ = ["verify_signature", "parse_github_event"]
