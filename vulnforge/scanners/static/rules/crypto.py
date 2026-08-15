"""Weak / broken cryptography detection rules (CWE-327/326)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="crypto-md5",
        title="MD5 usage",
        description="The MD5 hash algorithm is cryptographically broken.",
        severity="medium",
        patterns=[
            r"(?i)hashlib\.md5\s*\(",
            r"(?i)\bmd5\s*\(",
            r"(?i)MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']",
        ],
        cwe="CWE-327",
        recommendation="Use SHA-256 or better for integrity; bcrypt/argon2 for passwords.",
    ),
    StaticRule(
        id="crypto-sha1",
        title="SHA-1 usage",
        description="SHA-1 is deprecated for security-sensitive use.",
        severity="low",
        patterns=[
            r"(?i)hashlib\.sha1\s*\(",
            r"(?i)\bsha1\s*\(",
            r"(?i)MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']",
        ],
        cwe="CWE-327",
        recommendation="Migrate to SHA-256 or SHA-3.",
    ),
    StaticRule(
        id="crypto-des",
        title="DES / 3DES usage",
        description="DES and 3DES are considered weak block ciphers.",
        severity="medium",
        patterns=[
            r"(?i)\bDES(?:ede)?\b",
            r"(?i)Cipher\.getInstance\s*\(\s*[\"']DES",
        ],
        cwe="CWE-327",
        recommendation="Use AES-GCM or ChaCha20-Poly1305.",
    ),
    StaticRule(
        id="crypto-rc4",
        title="RC4 usage",
        description="RC4 is a broken stream cipher.",
        severity="high",
        patterns=[r"(?i)\b(?:ARC4|RC4|arc4)\b"],
        cwe="CWE-327",
        recommendation="Replace RC4 with a modern AEAD cipher.",
    ),
    StaticRule(
        id="crypto-ecb-mode",
        title="ECB block cipher mode",
        description="ECB mode leaks patterns in plaintext.",
        severity="high",
        patterns=[
            r"(?i)MODE_ECB",
            r"(?i)/ECB/",
            r"(?i)Cipher\.getInstance\s*\(\s*[\"'][^\"']*ECB",
        ],
        cwe="CWE-327",
        recommendation="Use an authenticated mode such as GCM or CBC with IV.",
    ),
    StaticRule(
        id="crypto-fixed-iv",
        title="Hardcoded/fixed IV",
        description="A hardcoded initialization vector (IV) was found.",
        severity="medium",
        patterns=[r"(?i)\biv\s*=\s*(?:b?[\"'][0-9a-fA-F]{16,}[\"']|b?[\"'][^\"']{8,}[\"'])"],
        cwe="CWE-326",
        recommendation="Generate a fresh random IV per encryption operation.",
    ),
]

__all__ = ["RULES"]
