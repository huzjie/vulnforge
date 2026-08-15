"""Insecure deserialization detection rules (CWE-502)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="deser-pickle-load",
        title="Unsafe pickle deserialization",
        description="pickle.load/loads deserializes untrusted data.",
        severity="critical",
        patterns=[r"(?i)pickle\.(load|loads)\s*\("],
        cwe="CWE-502",
        recommendation="Do not unpickle untrusted data; use a safe serialization format.",
    ),
    StaticRule(
        id="deser-yaml-load",
        title="Unsafe yaml.load",
        description="yaml.load without SafeLoader can instantiate arbitrary objects.",
        severity="high",
        patterns=[r"(?i)yaml\.load\s*\("],
        cwe="CWE-502",
        recommendation="Use yaml.safe_load for untrusted input.",
    ),
    StaticRule(
        id="deser-eval",
        title="eval() on data",
        description="eval() evaluates arbitrary expressions.",
        severity="critical",
        patterns=[r"(?i)\beval\s*\("],
        cwe="CWE-502",
        recommendation="Avoid eval(); parse input with a safe parser.",
    ),
    StaticRule(
        id="deser-marshal",
        title="marshal.load usage",
        description="marshal.load/loads can be unsafe on untrusted data.",
        severity="high",
        patterns=[r"(?i)marshal\.(load|loads)\s*\("],
        cwe="CWE-502",
        recommendation="Avoid marshal for untrusted input.",
    ),
    StaticRule(
        id="deser-java-objectinput",
        title="Java ObjectInputStream / readObject",
        description="Java native deserialization of untrusted streams.",
        severity="high",
        patterns=[r"(?i)\bObjectInputStream\s*\(", r"(?i)\breadObject\s*\("],
        cwe="CWE-502",
        recommendation="Validate/filter serialized streams; prefer JSON.",
        extensions=[".java"],
    ),
    StaticRule(
        id="deser-jsonpickle",
        title="jsonpickle decode",
        description="jsonpickle can execute code when decoding untrusted JSON.",
        severity="medium",
        patterns=[r"(?i)jsonpickle\.(decode|loads)\s*\("],
        cwe="CWE-502",
        recommendation="Use plain json.loads for untrusted data.",
    ),
]

__all__ = ["RULES"]
