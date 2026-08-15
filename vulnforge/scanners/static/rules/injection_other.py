"""Other injection flaws: code/eval/template/LDAP/XXE (CWE-94/95/90/611)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="inj-eval",
        title="Dynamic code evaluation (eval)",
        description="eval() executes untrusted input as code.",
        severity="critical",
        patterns=[r"(?i)\beval\s*\("],
        cwe="CWE-95",
        recommendation="Avoid eval(); use safe parsers.",
    ),
    StaticRule(
        id="inj-exec",
        title="Dynamic code execution (exec)",
        description="exec() executes arbitrary code.",
        severity="critical",
        patterns=[r"(?i)\bexec\s*\("],
        cwe="CWE-94",
        recommendation="Avoid exec(); prefer explicit, safe logic.",
    ),
    StaticRule(
        id="inj-template-injection",
        title="Server-side template injection",
        description="A template engine is fed user-controlled input.",
        severity="high",
        patterns=[
            r"(?i)render_template_string\s*\(",
            r"(?i)jinja2\.Template\s*\(",
            r"(?i)\bTemplate\s*\(\s*[^)]*(request|input|param|user)\b",
        ],
        cwe="CWE-94",
        recommendation="Do not render user input as templates; sandbox or escape.",
    ),
    StaticRule(
        id="inj-ldap",
        title="LDAP injection",
        description="An LDAP search uses user-controlled filter input.",
        severity="high",
        patterns=[
            r"(?i)(ldap\.search|search_s|search_ext)\s*\([^)]*(request|input|param|user|filter)\b"
        ],
        cwe="CWE-90",
        recommendation="Escape LDAP filter special characters.",
    ),
    StaticRule(
        id="inj-xxe",
        title="XML External Entity (XXE) risk",
        description="An XML parser may process external entities.",
        severity="high",
        patterns=[
            r"(?i)(lxml\.(?:etree\.)?(?:parse|fromstring|XMLParser)\s*\(|xml\.etree\.ElementTree\.(?:parse|fromstring)\s*\(|etree\.parse\s*\()"
        ],
        cwe="CWE-611",
        recommendation="Disable external entity resolution / use a hardened parser.",
    ),
    StaticRule(
        id="inj-xxe-java",
        title="XML parser without XXE hardening",
        description="A Java XML parser factory may be vulnerable to XXE.",
        severity="high",
        patterns=[
            r"(?i)(DocumentBuilderFactory|SAXParserFactory|XMLReaderFactory|TransformerFactory)"
        ],
        cwe="CWE-611",
        recommendation="Disable DOCTYPE and external entities in the factory.",
        extensions=[".java"],
    ),
]

__all__ = ["RULES"]
