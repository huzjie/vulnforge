"""OpenAI-compatible chat completions provider.

Works against any service exposing the ``/chat/completions`` endpoint (OpenAI,
GLM/Zhipu, DeepSeek, Qwen/DashScope, vLLM, LM Studio, ...).  Network I/O uses
only :mod:`urllib.request`; all failures are surfaced as
:class:`vulnforge.errors.ProviderError`.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict

from vulnforge.errors import ProviderError

from .base import BaseProvider

# Environment variables checked (in order) when ``api_key`` is absent from cfg.
_API_KEY_ENV_VARS = (
    "OPENAI_API_KEY",
    "GLM_API_KEY",
    "DEEPSEEK_API_KEY",
    "QWEN_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
)


class OpenAICompatProvider(BaseProvider):
    """Provider for any OpenAI-compatible ``/chat/completions`` API."""

    name = "openai_compat"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        super().__init__(cfg)
        self.base_url: str = (cfg.get("base_url") or "https://api.openai.com/v1").rstrip("/")
        self.model: str = cfg.get("model") or "gpt-4o-mini"
        self.api_key: str = self._resolve_api_key(cfg)
        self.timeout: float = float(cfg.get("timeout", 60))
        self.temperature: float = float(cfg.get("temperature", 0.0))
        self.max_tokens: int = int(cfg.get("max_tokens", 2048))

    @staticmethod
    def _resolve_api_key(cfg: Dict[str, Any]) -> str:
        key = cfg.get("api_key") or ""
        if key:
            return key
        for var in _API_KEY_ENV_VARS:
            value = os.environ.get(var)
            if value:
                return value
        return ""

    def complete(self, prompt: str, system: str = "") -> str:
        """Send a chat completion request and return the assistant content."""
        if not self.api_key:
            raise ProviderError(
                f"{self.name}: missing api_key (set it in config or via "
                f"{'/'.join(_API_KEY_ENV_VARS)})"
            )

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        url = f"{self.base_url}/chat/completions"
        body = self._post(url, payload)

        try:
            obj = json.loads(body)
            content = obj["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ProviderError(f"{self.name}: unexpected response: {body[:500]!r}") from exc

        if content is None:
            raise ProviderError(f"{self.name}: empty content in response")
        return content

    def _post(self, url: str, payload: Dict[str, Any]) -> str:
        """Perform a JSON POST request and return the decoded text body."""
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
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
