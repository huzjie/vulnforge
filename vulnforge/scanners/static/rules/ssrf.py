"""Server-Side Request Forgery (SSRF) detection rules (CWE-918)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="ssrf-requests-get",
        title="requests.get with user-controlled URL",
        description="An HTTP request is made to a potentially user-controlled URL.",
        severity="high",
        patterns=[
            r"(?i)requests\.(get|post|put|delete|head|patch)\s*\(\s*[^)]*(request|input|param|url|target|host|link)\b"
        ],
        cwe="CWE-918",
        recommendation="Validate the URL against an allowlist; block internal IPs.",
    ),
    StaticRule(
        id="ssrf-urllib",
        title="urllib.urlopen with user-controlled URL",
        description="urlopen is called with a potentially user-controlled URL.",
        severity="high",
        patterns=[
            r"(?i)urllib(?:\.request)?\.urlopen\s*\(\s*[^)]*(request|input|param|url|target|host)\b"
        ],
        cwe="CWE-918",
        recommendation="Restrict URLs to trusted hosts only.",
    ),
    StaticRule(
        id="ssrf-http-client",
        title="HTTP client with user-controlled URL",
        description="A generic HTTP client/fetch is called with user input.",
        severity="high",
        patterns=[
            r"(?i)(http_client|HttpClient|fetch)\s*\(\s*[^)]*(request|input|param|url|target|host)\b"
        ],
        cwe="CWE-918",
        recommendation="Validate and allowlist target URLs.",
    ),
    StaticRule(
        id="ssrf-url-concat",
        title="URL built by concatenation",
        description="An HTTP URL is built by concatenating input.",
        severity="medium",
        patterns=[
            r'(?i)(requests\.(?:get|post)|urlopen)\s*\(\s*["\']https?://["\']\s*\+'
        ],
        cwe="CWE-918",
        recommendation="Avoid string-building URLs; use validated URL objects.",
    ),
]

__all__ = ["RULES"]
