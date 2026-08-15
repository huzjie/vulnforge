"""Hardcoded secrets and credential detection rules (CWE-798)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="secrets-aws-access-key",
        title="AWS Access Key ID exposed",
        description="A hardcoded AWS Access Key ID (AKIA...) was found.",
        severity="critical",
        patterns=[r"AKIA[0-9A-Z]{16}"],
        cwe="CWE-798",
        recommendation="Use IAM roles or a secrets manager; rotate the exposed key.",
    ),
    StaticRule(
        id="secrets-aws-secret-key",
        title="AWS Secret Access Key exposed",
        description="A hardcoded AWS secret access key assignment was found.",
        severity="critical",
        patterns=[r"(?i)aws_secret_access_key\s*[:=]\s*[\"'][A-Za-z0-9/+]{40}[\"']"],
        cwe="CWE-798",
        recommendation="Rotate the key and move it to a secrets manager.",
    ),
    StaticRule(
        id="secrets-github-token",
        title="GitHub personal access token exposed",
        description="A GitHub token (ghp_/gho_/github_pat_) was found.",
        severity="critical",
        patterns=[
            r"gh[pousr]_[A-Za-z0-9]{36,255}",
            r"github_pat_[A-Za-z0-9_]{22,255}",
        ],
        cwe="CWE-798",
        recommendation="Revoke the token immediately and store it securely.",
    ),
    StaticRule(
        id="secrets-google-api-key",
        title="Google API key exposed",
        description="A Google API key (AIza...) was found.",
        severity="high",
        patterns=[r"AIza[0-9A-Za-z\-_]{35}"],
        cwe="CWE-798",
        recommendation="Restrict the API key and rotate it.",
    ),
    StaticRule(
        id="secrets-slack-token",
        title="Slack token exposed",
        description="A Slack token (xox[baprs]-...) was found.",
        severity="high",
        patterns=[r"xox[baprs]-[0-9A-Za-z\-]{10,}"],
        cwe="CWE-798",
        recommendation="Revoke the token and use environment variables.",
    ),
    StaticRule(
        id="secrets-stripe-key",
        title="Stripe live secret key exposed",
        description="A Stripe live secret key (sk_live_/rk_live_) was found.",
        severity="critical",
        patterns=[r"(?:sk|rk)_live_[0-9a-zA-Z]{16,}"],
        cwe="CWE-798",
        recommendation="Roll the Stripe key immediately.",
    ),
    StaticRule(
        id="secrets-private-key",
        title="Private key material exposed",
        description="A PEM/OpenSSH private key block was found.",
        severity="critical",
        patterns=[r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"],
        cwe="CWE-798",
        recommendation="Remove the private key from source control.",
    ),
    StaticRule(
        id="secrets-password-assignment",
        title="Hardcoded password/secret assignment",
        description="A variable named password/secret/token is assigned a literal.",
        severity="high",
        patterns=[
            r"(?i)\b(password|passwd|pwd|secret|api_key|apikey|access_token|auth_token)\b\s*[:=]\s*[\"'][^\"']{4,}[\"']"
        ],
        cwe="CWE-798",
        recommendation="Use environment variables or a secrets manager.",
    ),
    StaticRule(
        id="secrets-jwt",
        title="Hardcoded JWT token",
        description="A JSON Web Token (eyJ...) was found in code.",
        severity="medium",
        patterns=[r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"],
        cwe="CWE-798",
        recommendation="Do not embed tokens; generate them at runtime.",
    ),
    StaticRule(
        id="secrets-npm-auth-token",
        title="npm auth token exposed",
        description="An npm registry _authToken was found.",
        severity="high",
        patterns=[
            r"(?i)(//[^\s]*:_authToken\s*=|[Nn]pm[_]?[Aa]uth[_]?[Tt]oken\s*[:=]\s*)[\"']?[A-Za-z0-9\-_]{20,}[\"']?"
        ],
        cwe="CWE-798",
        recommendation="Move npm tokens to a credentials store.",
    ),
    StaticRule(
        id="secrets-ssh-private-key",
        title="OpenSSH private key exposed",
        description="An OpenSSH private key block was found.",
        severity="critical",
        patterns=[r"-----BEGIN OPENSSH PRIVATE KEY-----"],
        cwe="CWE-798",
        recommendation="Remove the key and rotate it.",
    ),
    StaticRule(
        id="secrets-twilio",
        title="Twilio API credentials exposed",
        description="A Twilio Account SID or Auth Token was found.",
        severity="high",
        patterns=[r"SK[0-9a-fA-F]{32}", r"AC[0-9a-fA-F]{32}"],
        cwe="CWE-798",
        recommendation="Rotate the Twilio credentials.",
    ),
    StaticRule(
        id="secrets-sendgrid",
        title="SendGrid API key exposed",
        description="A SendGrid API key (SG.xxx.yyy) was found.",
        severity="high",
        patterns=[r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"],
        cwe="CWE-798",
        recommendation="Rotate the SendGrid key.",
    ),
    StaticRule(
        id="secrets-heroku",
        title="Heroku API key exposed",
        description="A Heroku API key was found.",
        severity="high",
        patterns=[r"(?i)heroku\s*[:=]\s*[\"']?[0-9a-fA-F\-]{36}"],
        cwe="CWE-798",
        recommendation="Rotate the Heroku key.",
    ),
    StaticRule(
        id="secrets-generic-api-key",
        title="Generic API key exposed",
        description="A generic api_key/secret_key literal assignment was found.",
        severity="medium",
        patterns=[
            r"(?i)\b(api[_-]?key|apikey|secret[_-]?key)\b\s*[:=]\s*[\"'][A-Za-z0-9/+_\-]{16,}[\"']"
        ],
        cwe="CWE-798",
        recommendation="Use a secrets manager instead of hardcoding keys.",
    ),
]

__all__ = ["RULES"]
