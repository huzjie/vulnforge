"""Command injection detection rules (CWE-78)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="cmd-os-system",
        title="os.system with concatenation",
        description="os.system() is called with a concatenated command string.",
        severity="critical",
        patterns=[r"(?i)os\.system\s*\(\s*[^)]*\+"],
        cwe="CWE-78",
        recommendation="Use subprocess with an argument list (shell=False).",
    ),
    StaticRule(
        id="cmd-subprocess-shell",
        title="subprocess with shell=True",
        description="subprocess is invoked with shell=True.",
        severity="high",
        patterns=[
            r"(?i)subprocess\.(?:call|check_call|check_output|run|Popen)\s*\([^)]*shell\s*=\s*True"
        ],
        cwe="CWE-78",
        recommendation="Avoid shell=True; pass arguments as a list.",
    ),
    StaticRule(
        id="cmd-subprocess-concat",
        title="subprocess with concatenated command",
        description="subprocess command is built via string concatenation.",
        severity="high",
        patterns=[
            r"(?i)subprocess\.(?:call|check_call|check_output|run|Popen)\s*\([^)]*\+"
        ],
        cwe="CWE-78",
        recommendation="Pass an argument list without string building.",
    ),
    StaticRule(
        id="cmd-exec",
        title="exec() usage",
        description="exec() executes an arbitrary string as code.",
        severity="high",
        patterns=[r"(?i)\bexec\s*\("],
        cwe="CWE-78",
        recommendation="Avoid exec() on untrusted input.",
    ),
    StaticRule(
        id="cmd-popen-shell",
        title="os.popen with concatenation",
        description="os.popen() is called with a concatenated command string.",
        severity="high",
        patterns=[r"(?i)os\.popen\s*\(\s*[^)]*\+"],
        cwe="CWE-78",
        recommendation="Use subprocess.run with an argument list.",
    ),
]

__all__ = ["RULES"]
