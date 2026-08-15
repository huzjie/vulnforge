"""A tiny TTL-backed JSON cache.

Values are stored in a single JSON file (default ``~/.vulnforge/cache.json``)
alongside an expiry timestamp.  Expired entries are lazily dropped on read.
"""

import json
import os
import time
from typing import Any, Optional

DEFAULT_CACHE_PATH = os.path.expanduser("~/.vulnforge/cache.json")


class JsonCache:
    """Key/value cache persisted to a JSON file with per-entry TTL."""

    def __init__(self, path: Optional[str] = None, ttl: float = 86400.0) -> None:
        self.path: str = path or DEFAULT_CACHE_PATH
        self.ttl: float = float(ttl)
        self._data: dict = self._load()

    def get(self, key: str) -> Any:
        """Return the value for ``key`` or ``None`` if absent/expired."""
        entry = self._data.get(key)
        if not isinstance(entry, dict):
            return None
        if entry.get("expires", 0.0) < time.time():
            self._data.pop(key, None)
            return None
        return entry.get("value")

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Store ``value`` under ``key`` with a TTL (defaults to the cache TTL)."""
        effective_ttl = self.ttl if ttl is None else float(ttl)
        self._data[key] = {
            "value": value,
            "expires": time.time() + effective_ttl,
        }
        self._save()

    def delete(self, key: str) -> None:
        """Remove ``key`` from the cache."""
        if key in self._data:
            del self._data[key]
            self._save()

    def clear(self) -> None:
        """Drop all cached entries."""
        self._data = {}
        self._save()

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def _save(self) -> None:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp_path = self.path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, ensure_ascii=False)
        os.replace(tmp_path, self.path)
