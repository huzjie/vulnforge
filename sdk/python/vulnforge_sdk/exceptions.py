"""vulnforge Python SDK 异常。"""

from __future__ import annotations

from typing import Any, Optional


class VulnforgeAPIError(Exception):
    """调用 vulnforge API 出错时抛出。"""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


__all__ = ["VulnforgeAPIError"]
