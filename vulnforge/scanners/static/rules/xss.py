"""Cross-site scripting (XSS) detection rules (CWE-79)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="xss-innerhtml",
        title="Unsafe innerHTML assignment",
        description="innerHTML is assigned, potentially with unescaped user data.",
        severity="high",
        patterns=[r"(?i)\.innerHTML\s*="],
        cwe="CWE-79",
        recommendation="Use textContent or sanitize with a DOM purifier.",
    ),
    StaticRule(
        id="xss-document-write",
        title="document.write usage",
        description="document.write can inject unescaped content into the page.",
        severity="medium",
        patterns=[r"(?i)document\.write\s*\("],
        cwe="CWE-79",
        recommendation="Avoid document.write; prefer DOM APIs.",
    ),
    StaticRule(
        id="xss-dangerously-set-inner-html",
        title="dangerouslySetInnerHTML usage",
        description="React dangerouslySetInnerHTML bypasses escaping.",
        severity="high",
        patterns=[r"dangerouslySetInnerHTML"],
        cwe="CWE-79",
        recommendation="Avoid dangerouslySetInnerHTML or sanitize the content.",
    ),
    StaticRule(
        id="xss-insert-adjacent-html",
        title="insertAdjacentHTML usage",
        description="insertAdjacentHTML inserts raw HTML strings.",
        severity="medium",
        patterns=[r"(?i)\.insertAdjacentHTML\s*\("],
        cwe="CWE-79",
        recommendation="Prefer createElement / textContent.",
    ),
    StaticRule(
        id="xss-unescaped-output",
        title="Unescaped template output",
        description="Template syntax renders unescaped output (v-html, <%=, |safe).",
        severity="medium",
        patterns=[
            r"(?i)\bv-html\s*=",
            r"<%=\s*",
            r"\{\{\s*[^}]*\|\s*safe\s*\}\}",
        ],
        cwe="CWE-79",
        recommendation="Escape output or use auto-escaping templates.",
    ),
]

__all__ = ["RULES"]
