"""Hardcoded secrets / credentials scanner.

Combines two detection strategies: (1) a curated set of known secret prefixes
(GitHub, AWS, Slack, OpenAI, Google, Stripe, Twilio, JWT, private keys) and
(2) Shannon-entropy analysis of long tokens (entropy > 4.5).  Detected secrets
are reported as ``CWE-798`` findings with the secret value redacted to avoid
leaking credentials into reports.
"""

import math
import re
from typing import Any, Dict, List, Tuple

from vulnforge.models import Finding, Severity
from vulnforge.scanners.base import BaseScanner
from vulnforge.scanners.registry import register

ENTROPY_THRESHOLD = 4.5
MIN_TOKEN_LENGTH = 16

# (rule suffix, compiled regex) for known secret prefixes.
_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("github-pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("github-token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("openai-key", re.compile(r"\bsk-(?:live-|proj-)?[A-Za-z0-9]{20,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("stripe-key", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("twilio-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-]{%d,}" % MIN_TOKEN_LENGTH)


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy (bits per character) of ``text``."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _redact(secret: str) -> str:
    """Return a redacted version of a secret (first 4 chars + mask)."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 4)


@register
class SecretsScanner(BaseScanner):
    """Detect hardcoded secrets via prefixes and entropy."""

    name = "secrets"

    def scan(self, targets, config: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        for _target, file_path in self._iter_files(targets):
            file_path = str(file_path)
            try:
                with open(file_path, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            findings.extend(self._scan_lines(file_path, lines))
        return findings

    def _scan_lines(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        covered: List[Tuple[int, int]] = []  # (line_index, start, end) spans

        for line_no, line in enumerate(lines, start=1):
            # 1. Known-prefix patterns.
            for suffix, pattern in _PATTERNS:
                for m in pattern.finditer(line):
                    secret = m.group(0)
                    findings.append(
                        self._make_finding(
                            file_path, line_no, m.start(), line, secret,
                            rule_suffix=suffix,
                            severity=Severity.HIGH,
                            title=f"检测到疑似硬编码密钥（{suffix}）",
                        )
                    )
                    covered.append((line_no, m.start(), m.end()))

            # 2. High-entropy tokens not already covered by a prefix match.
            for m in _TOKEN_RE.finditer(line):
                token = m.group(0)
                if any(
                    ln == line_no and not (m.end() <= s or m.start() >= e)
                    for ln, s, e in covered
                ):
                    continue
                if shannon_entropy(token) <= ENTROPY_THRESHOLD:
                    continue
                findings.append(
                    self._make_finding(
                        file_path, line_no, m.start(), line, token,
                        rule_suffix="high-entropy",
                        severity=Severity.MEDIUM,
                        title="检测到高熵字符串（疑似密钥/令牌）",
                    )
                )
                covered.append((line_no, m.start(), m.end()))

        return findings

    def _make_finding(self, file_path: str, line_no: int, column: int, line: str,
                      secret: str, rule_suffix: str, severity: Severity,
                      title: str) -> Finding:
        redacted_line = line.replace(secret, _redact(secret), 1)
        return Finding(
            rule_id=f"secrets.{rule_suffix}",
            title=title,
            description=(
                f"在源码中发现疑似硬编码凭证（类型 {rule_suffix}），"
                f"熵值 {shannon_entropy(secret):.2f}。凭证已脱敏。"
            ),
            severity=severity,
            file_path=file_path,
            line=line_no,
            column=column,
            code=redacted_line.strip(),
            cwe="CWE-798",
            cvss=None,
            confidence=0.9,
            scanner="secrets",
            recommendation=(
                "移除硬编码凭证，改用环境变量或密钥管理服务（如 Vault / KMS / Secrets Manager），"
                "并立即轮换已泄露的密钥。"
            ),
            references=["https://cwe.mitre.org/data/definitions/798.html"],
            tags=["secret", "credential", rule_suffix],
            raw={
                "type": rule_suffix,
                "entropy": round(shannon_entropy(secret), 4),
                "secret": _redact(secret),
            },
        )
