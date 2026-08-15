"""Google Gemini provider.

Posts to ``/v1beta/models/{model}:generateContent?key={api_key}``.  The API key
is passed as a query parameter (not a header), per the Gemini REST API.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict

from vulnforge.errors import ProviderError

from .base import BaseProvider


class GeminiProvider(BaseProvider):
    """Provider for the Google Gemini ``generateContent`` REST API."""

    name = "gemini"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        super().__init__(cfg)
        self.base_url: str = (
            cfg.get("base_url") or "https://generativelanguage.googleapis.com"
        ).rstrip("/")
        self.model: str = cfg.get("model") or "gemini-1.5-flash"
        self.api_key: str = cfg.get("api_key") or os.environ.get("GEMINI_API_KEY") or ""
        self.timeout: float = float(cfg.get("timeout", 60))
        self.temperature: float = float(cfg.get("temperature", 0.0))
        self.max_tokens: int = int(cfg.get("max_tokens", 2048))

    def complete(self, prompt: str, system: str = "") -> str:
        """Send a generateContent request and return the generated text."""
        if not self.api_key:
            raise ProviderError(f"{self.name}: missing api_key (GEMINI_API_KEY)")

        parts = []
        if system:
            parts.append({"text": system + "\n\n"})
        parts.append({"text": prompt})

        payload = {
            "contents": [{"role": "user", "parts": parts}],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_tokens,
            },
        }

        url = f"{self.base_url}/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        body = self._post(url, payload)

        try:
            obj = json.loads(body)
            candidate = obj["candidates"][0]
            content = candidate["content"]
            text = "".join(
                part.get("text", "")
                for part in content.get("parts", [])
                if isinstance(part, dict)
            )
        except (KeyError, IndexError, TypeError, ValueError) as exc:
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
            headers={"Content-Type": "application/json"},
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
