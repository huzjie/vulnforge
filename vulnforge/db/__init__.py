"""Vulnerability database layer (offline-first).

Provides a TTL-backed :class:`JsonCache`, an :class:`OSVClient` for querying
the OSV.dev API (with graceful offline fallback), and a :class:`CVEDB` holding
a small built-in set of well-known CVE records.
"""

from .cache import JsonCache
from .cve import CVEDB
from .osv import OSVClient

__all__ = ["JsonCache", "OSVClient", "CVEDB"]
