"""Deterministic offline mock LLM provider.

:class:`MockProvider` never touches the network.  It inspects the prompt for a
small set of dangerous patterns and returns a fixed, deterministic JSON array
of ``0``--``2`` findings.  This keeps the whole pipeline runnable without any
API key or internet access.
"""

import json
from typing import Any, Dict, List

from .base import BaseProvider

# Deterministic findings keyed by a simple fingerprint of the prompt content.
# Each entry mirrors the fields understood by `vulnforge.scanners.llm`.
_FINDING_TEMPLATES: List[Dict[str, Any]] = [
    {
        "rule_id": "mock.eval-rce",
        "title": "Potential arbitrary code execution via eval()/exec()",
        "description": "User-controlled or untrusted data may reach eval()/exec(), "
        "allowing arbitrary code execution.",
        "severity": "critical",
        "cwe": "CWE-95",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "recommendation": "Avoid eval()/exec(); use a safe parser or ast.literal_eval.",
        "references": ["https://cwe.mitre.org/data/definitions/95.html"],
        "tags": ["rce", "injection"],
    },
    {
        "rule_id": "mock.pickle-deserialization",
        "title": "Insecure deserialization via pickle",
        "description": "pickle.loads() on untrusted input can execute arbitrary code.",
        "severity": "critical",
        "cwe": "CWE-502",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "recommendation": "Use a safe serialization format (e.g. JSON) or restrict input.",
        "references": ["https://cwe.mitre.org/data/definitions/502.html"],
        "tags": ["deserialization", "rce"],
    },
    {
        "rule_id": "mock.subprocess-injection",
        "title": "Command injection via subprocess/os.system",
        "description": "Shell command construction may concatenate untrusted input, "
        "leading to command injection.",
        "severity": "high",
        "cwe": "CWE-78",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "recommendation": "Avoid shell=True and pass arguments as a list; sanitize input.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
        "tags": ["rce", "injection"],
    },
    {
        "rule_id": "mock.md5-weak-crypto",
        "title": "Use of cryptographically weak hash (MD5)",
        "description": "MD5 is considered broken and unsuitable for security-critical use.",
        "severity": "medium",
        "cwe": "CWE-328",
        "cvss": None,
        "recommendation": "Use SHA-256 or a modern password hashing function (argon2, bcrypt).",
        "references": ["https://cwe.mitre.org/data/definitions/328.html"],
        "tags": ["crypto"],
    },
    {
        "rule_id": "mock.innerhtml-xss",
        "title": "Cross-site scripting via innerHTML",
        "description": "Assigning untrusted data to innerHTML can inject script.",
        "severity": "high",
        "cwe": "CWE-79",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        "recommendation": "Use textContent or a framework that escapes output.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
        "tags": ["xss", "web"],
    },
    {
        "rule_id": "mock.sql-injection",
        "title": "SQL injection via string concatenation",
        "description": "SQL query is built by concatenating user input, allowing SQL injection.",
        "severity": "high",
        "cwe": "CWE-89",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "recommendation": "Use parameterized queries / prepared statements.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        "tags": ["sql", "injection"],
    },
]

def _detect(prompt: str) -> List[Dict[str, Any]]:
    """Return 0--2 deterministic findings based on prompt contents."""
    lower = prompt.lower()
    hits: List[Dict[str, Any]] = []

    def _push(idx: int) -> None:
        tpl = _FINDING_TEMPLATES[idx]
        if not any(f["rule_id"] == tpl["rule_id"] for f in hits):
            hits.append(dict(tpl))

    if "eval(" in prompt or "exec(" in prompt:
        _push(0)
    if "pickle" in lower:
        _push(1)
    if ("subprocess" in lower) or ("os.system" in lower) or ("shell=true" in lower):
        _push(2)
    if "md5" in lower:
        _push(3)
    if "innerhtml" in lower:
        _push(4)
    if ("select" in lower and "from" in lower and
            ("+" in prompt or "format(" in lower or "%" in prompt or "f\"" in prompt)):
        _push(5)

    return hits[:2]


class MockProvider(BaseProvider):
    """Fully-offline deterministic provider used for testing and CI."""

    name = "mock"

    def complete(self, prompt: str, system: str = "") -> str:
        """Return a deterministic JSON array of findings for ``prompt``."""
        findings = _detect(prompt)
        return json.dumps(findings, ensure_ascii=False)
