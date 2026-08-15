"""OSV.dev API client with offline-first caching.

Queries ``https://api.osv.dev/v1/query`` using only :mod:`urllib.request`.  On
any network/timeout error it silently returns an empty list and relies on the
:class:`JsonCache` for previously fetched results, so scans never fail because
the network is unavailable.
"""

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .cache import JsonCache


class OSVClient:
    """Client for the OSV.dev vulnerability API."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        cache: Optional[JsonCache] = None,
    ) -> None:
        config = config or {}
        dep_cfg: Dict[str, Any] = config.get("dependency", {}) or {}
        self.endpoint: str = dep_cfg.get("osv_endpoint") or "https://api.osv.dev/v1/query"
        self.timeout: float = float(dep_cfg.get("osv_timeout", 10))
        self.cache: JsonCache = cache or JsonCache()
        self.offline: bool = bool(dep_cfg.get("offline", True))

    def query(self, package: str, version: str, ecosystem: str = "") -> List[Dict[str, Any]]:
        """Query OSV for vulnerabilities affecting ``package@version``.

        Returns an empty list when offline, on network failure, or when no
        vulnerabilities are known.
        """
        ecosystem = ecosystem or "PyPI"
        cache_key = f"osv:{ecosystem}:{package}@{version}"

        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached if isinstance(cached, list) else []

        if self.offline:
            return []

        payload = {
            "version": version,
            "package": {"name": package, "ecosystem": ecosystem},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
            obj = json.loads(body)
            vulns = obj.get("vulns", []) if isinstance(obj, dict) else []
            if not isinstance(vulns, list):
                vulns = []
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                OSError, ValueError):
            vulns = []

        self.cache.set(cache_key, vulns)
        return vulns

    def query_batch(self, pkgs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Query OSV for a list of package specs.

        Each spec is a dict with ``package``, ``version`` and optional
        ``ecosystem`` keys; the result appends a ``vulns`` key to each spec.
        """
        results: List[Dict[str, Any]] = []
        for spec in pkgs:
            package = spec.get("package") or spec.get("name") or ""
            version = spec.get("version") or ""
            ecosystem = spec.get("ecosystem") or ""
            if not package or not version:
                continue
            vulns = self.query(package, version, ecosystem)
            results.append({**spec, "vulns": vulns})
        return results
