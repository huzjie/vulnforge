"""Python-specific vulnerability detection rules (CWE-295/377/330)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="py-verify-false",
        title="TLS certificate verification disabled",
        description="SSL certificate verification is disabled (verify=False).",
        severity="medium",
        patterns=[r"(?i)verify\s*=\s*False"],
        cwe="CWE-295",
        recommendation="Keep certificate verification enabled; pin trusted CAs.",
        extensions=[".py"],
    ),
    StaticRule(
        id="py-unsafe-tempfile",
        title="Insecure temporary file",
        description="mktemp/mkstemp creates a predictable or world-readable temp file.",
        severity="medium",
        patterns=[
            r"(?i)tempfile\.(mktemp|mkstemp)\s*\(",
            r"(?i)\b(mktemp|mkstemp)\s*\(",
        ],
        cwe="CWE-377",
        recommendation="Use tempfile.NamedTemporaryFile with safe permissions.",
        extensions=[".py"],
    ),
    StaticRule(
        id="py-random-security",
        title="Insecure randomness for security",
        description="The random module is used in a security-sensitive context.",
        severity="low",
        patterns=[
            r"(?i)\brandom\.(random|choice|randint|randrange|sample|shuffle|getrandbits)\s*\("
        ],
        cwe="CWE-330",
        recommendation="Use the secrets module for security-sensitive randomness.",
        extensions=[".py"],
    ),
]

__all__ = ["RULES"]
