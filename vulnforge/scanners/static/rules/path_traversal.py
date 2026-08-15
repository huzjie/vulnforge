"""Path traversal detection rules (CWE-22)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="path-traversal-open-concat",
        title="open() with concatenated path",
        description="open() is called with a concatenated, potentially user-controlled path.",
        severity="high",
        patterns=[
            r"(?i)\bopen\s*\(\s*[^)]*\+[^)]*\)",
            r"(?i)\bopen\s*\(\s*f[\"']",
        ],
        cwe="CWE-22",
        recommendation="Validate and canonicalize paths; reject '..' and absolute paths.",
    ),
    StaticRule(
        id="path-traversal-join-input",
        title="os.path.join with user input",
        description="os.path.join mixes a base path with user-controlled input.",
        severity="high",
        patterns=[
            r"(?i)os\.path\.join\s*\([^)]*(request|input|param|user|filename|file|path|name)\b"
        ],
        cwe="CWE-22",
        recommendation="Use path resolution + allowlist validation.",
    ),
    StaticRule(
        id="path-traversal-dotdot",
        title="Path traversal sequence",
        description="A '../' or '..\\' traversal sequence was found.",
        severity="low",
        patterns=[r"(\.\./|\.\.\\)"],
        cwe="CWE-22",
        recommendation="Sanitize and reject traversal sequences.",
    ),
    StaticRule(
        id="path-traversal-send-file",
        title="send_file with user input",
        description="send_file is called with a potentially user-controlled path.",
        severity="high",
        patterns=[r"(?i)send_file\s*\(\s*[^)]*(request|param|path|filename)\b"],
        cwe="CWE-22",
        recommendation="Restrict send_file to an allowlist of safe files.",
    ),
    StaticRule(
        id="path-traversal-file-read",
        title="File read with user input",
        description="A file read API is called with user-controlled input.",
        severity="high",
        patterns=[
            r"(?i)(read_text|read_bytes|read)\s*\(\s*[^)]*(request|param|input)\b"
        ],
        cwe="CWE-22",
        recommendation="Validate the path against an allowlist.",
    ),
]

__all__ = ["RULES"]
