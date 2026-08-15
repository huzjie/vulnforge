"""Anthropic Messages API provider.

Posts to ``/v1/messages`` using the ``x-api-key`` header (no ``Authorization``
bearer).  Only :mod:`urllib.request` is used for I/O.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict

from vulnforge.errors import ProviderError

from .base import BaseProvider


class AnthropicProvider(BaseProvider):
    """Provider for the Anthropic Messages API."""

    name = "anthropic"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        super().__init__(cfg)
        self.base_url: str = (cfg.get("base_url") or "https://api.anthropic.com").rstrip("/")
        self.model: str = cfg.get("model") or "claude-sonnet-4-20250514"
        self.api_key: str = cfg.get("api_key") or os.environ.get("ANTHROPIC_API_KEY") or ""
        self.version: str = cfg.get("anthropic_version") or "2023-06-01"
        self.timeout: float = float(cfg.get("timeout", 60))
        self.max_tokens: int = int(cfg.get("max_tokens", 4096))
        self.temperature: float = float(cfg.get("temperature", 0.0))

    def complete(self, prompt: str, system: str = "") -> str:
        """Send a Messages request and return the concatenated text content."""
        if not self.api_key:
            raise ProviderError(f"{self.name}: missing api_key (ANTHROPIC_API_KEY)")

        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        url = f"{self.base_url}/v1/messages"
        body = self._post(url, payload)

        try:
            obj = json.loads(body)
            blocks = obj["content"]
            text = "".join(
                block.get("text", "")
                for block in blocks
                if isinstance(block, dict) and block.get("type") == "text"
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderError(f"{self.name}: unexpected response: {body[:500]!r}") from exc

        if not text:
            raise ProviderError(f"{self.name}: empty content in response")
        return text

    def _post(self, url: str, payload: Dict[str, Any]) -> str:
        """Perform a JSON POST request and return the decoded text body."""
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": self.version,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            raise ProviderError(
                f"{self.name}: HTTP {exc.code} from {url}: {detail}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderError(f"{self.name}: request to {url} failed: {exc}") from exc
