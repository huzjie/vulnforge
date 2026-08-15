"""Authentication weakness detection rules (CWE-798/287)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="auth-hardcoded-credential",
        title="Hardcoded credential",
        description="A credential-like variable is assigned a literal value.",
        severity="high",
        patterns=[
            r"(?i)\b(admin_password|root_password|db_password|database_password|master_password)\b\s*[:=]\s*[\"'][^\"']+[\"']"
        ],
        cwe="CWE-798",
        recommendation="Load credentials from a secure store at runtime.",
    ),
    StaticRule(
        id="auth-default-credentials",
        title="Default credentials",
        description="Default username/password (e.g. admin/admin) detected.",
        severity="high",
        patterns=[
            r"(?i)(username|user|login)\s*=\s*[\"']admin[\"'][^\n]*(password|passwd)\s*=\s*[\"']admin[\"']"
        ],
        cwe="CWE-287",
        recommendation="Remove default credentials and enforce strong ones.",
    ),
    StaticRule(
        id="auth-insecure-eq-compare",
        title="Insecure password comparison",
        description="A password/hash is compared using '==' instead of a constant-time compare.",
        severity="medium",
        patterns=[
            r"(?i)\b(password|passwd|token|secret|hash|digest)\b\s*==\s*[\"'][^\"']+[\"']"
        ],
        cwe="CWE-287",
        recommendation="Use constant-time comparison (hmac.compare_digest).",
    ),
    StaticRule(
        id="auth-disabled-auth",
        title="Authentication disabled",
        description="Authentication appears to be disabled or bypassed.",
        severity="high",
        patterns=[
            r"(?i)\bauth\s*=\s*False",
            r"(?i)\bauthentication\s*=\s*False",
            r"(?i)\b(disable_?auth|skip_?auth|auth_?disabled)\b\s*=\s*True",
        ],
        cwe="CWE-287",
        recommendation="Do not disable authentication in production.",
    ),
    StaticRule(
        id="auth-hardcoded-secret-key",
        title="Hardcoded secret/session key",
        description="A secret/session/encryption key is hardcoded.",
        severity="high",
        patterns=[
            r"(?i)\b(secret_key|session_key|encryption_key|jwt_?secret|signing_key)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']"
        ],
        cwe="CWE-798",
        recommendation="Rotate the key and load it from the environment.",
    ),
]

__all__ = ["RULES"]
