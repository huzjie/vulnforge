"""Common Weakness Enumeration (CWE) lookup table.

Provides a static mapping of frequently-seen CWE identifiers to their
human-readable names plus a helper to resolve a CWE id to a name.
"""

from __future__ import annotations

from typing import Dict

CWE: Dict[str, str] = {
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-377": "Insecure Temporary File",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-415": "Double Free",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-601": "Open Redirect",
    "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


def cwe_name(cwe_id: str) -> str:
    """Resolve a CWE id (e.g. ``"CWE-79"`` or ``"79"``) to its name.

    Args:
        cwe_id: The CWE identifier, with or without the ``CWE-`` prefix.

    Returns:
        The human-readable CWE name, or the original ``cwe_id`` if unknown.
    """
    if not cwe_id:
        return cwe_id
    key = str(cwe_id).strip().upper()
    if not key.startswith("CWE"):
        key = "CWE-" + key.lstrip("-")
    return CWE.get(key, str(cwe_id))


__all__ = ["CWE", "cwe_name"]
