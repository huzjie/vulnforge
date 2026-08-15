"""Local Ollama provider.

Posts to ``http://host:11434/api/generate`` with ``stream: false`` and reads the
``response`` field.  No API key is required.
"""

import json
import urllib.error
import urllib.request
from typing import Any, Dict

from vulnforge.errors import ProviderError

from .base import BaseProvider


class OllamaProvider(BaseProvider):
    """Provider for a locally running Ollama server."""

    name = "ollama"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        super().__init__(cfg)
        base = (cfg.get("base_url") or "http://localhost:11434").rstrip("/")
        self.base_url: str = base
        self.model: str = cfg.get("model") or "llama3.1"
        self.timeout: float = float(cfg.get("timeout", 300))
        self.temperature: float = float(cfg.get("temperature", 0.0))

    def complete(self, prompt: str, system: str = "") -> str:
        """Send a generate request and return the ``response`` field."""
        if system:
            prompt = f"{system}\n\n{prompt}"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.temperature},
        }

        url = f"{self.base_url}/api/generate"
        body = self._post(url, payload)

        try:
            obj = json.loads(body)
            text = obj.get("response", "")
        except ValueError as exc:
            raise ProviderError(f"{self.name}: unexpected response: {body[:500]!r}") from exc

        if not text:
            raise ProviderError(f"{self.name}: empty response from Ollama")
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
            raise ProviderError(f"{self.name}: HTTP {exc.code} from {url}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderError(f"{self.name}: request to {url} failed: {exc}") from exc
