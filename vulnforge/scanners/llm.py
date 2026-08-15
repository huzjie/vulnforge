"""LLM-assisted vulnerability reasoning scanner.

Splits each code file into chunks, asks the configured LLM provider to return a
strict JSON array of findings, and maps the (possibly messy) model output into
:class:`vulnforge.models.Finding` objects.  Any provider failure degrades to a
warning and does not abort the overall scan.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from vulnforge.cvss.calculator import score_cvss31, severity_from_cvss
from vulnforge.errors import ProviderError
from vulnforge.llm import get_provider
from vulnforge.models import Finding, Severity
from vulnforge.scanners.base import BaseScanner
from vulnforge.scanners.registry import register

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "你是资深安全研究员，负责对代码进行漏洞挖掘。\n"
    "请严格只输出一个 JSON 数组，数组元素为 finding 对象，字段如下：\n"
    '{"rule_id": str, "title": str, "description": str, "severity": '
    '"info|low|medium|high|critical", "cwe": str, "cvss": str(可选), '
    '"line": int(可选), "code": str(可选), "recommendation": str, '
    '"references": [str], "tags": [str]}。\n'
    "不要输出任何解释性文字，不要使用 markdown 代码围栏，只输出 JSON。"
)

_SEVERITY_MAP = {
    "none": Severity.INFO,
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _to_severity(value: Any) -> Severity:
    """Coerce a model/severity string into a :class:`Severity` enum member."""
    if isinstance(value, Severity):
        return value
    if value is None:
        return Severity.MEDIUM
    return _SEVERITY_MAP.get(str(value).strip().lower(), Severity.MEDIUM)


def _extract_json(text: str) -> List[Any]:
    """Best-effort extraction of a JSON array from arbitrary model output."""
    if not text:
        return []

    # 1. Strip markdown code fences.
    fence_match = _FENCE_RE.search(text)
    if fence_match:
        text = fence_match.group(1)

    # 2. Try to parse the whole (stripped) text as JSON first; this handles a
    #    bare object/array without any surrounding prose or fences.
    stripped = text.strip()
    if stripped:
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]

    # 3. Otherwise snip from first '[' to last ']' (prose-wrapped array).
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return []
    candidate = text[start:end + 1]

    try:
        parsed = json.loads(candidate)
    except ValueError:
        return []

    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return [parsed]
    return []


@register
class LLMReasoningScanner(BaseScanner):
    """Use an LLM to reason about vulnerabilities in code chunks."""

    name = "llm"

    def scan(self, targets, config: Dict[str, Any]) -> List[Finding]:
        llm_cfg: Dict[str, Any] = config.get("llm", {}) or {}
        provider_key = llm_cfg.get("default_provider") or llm_cfg.get("provider") or "mock"
        providers: Dict[str, Any] = llm_cfg.get("providers", {}) or {}

        # Flatten: top-level llm settings + the selected provider's settings.
        provider_cfg = dict(llm_cfg)
        provider_cfg.pop("providers", None)
        provider_cfg.update(providers.get(provider_key, {}))
        provider_type = provider_cfg.get("type") or provider_key

        try:
            provider = get_provider(provider_type, provider_cfg)
        except Exception as exc:  # unknown provider etc.
            logger.warning("LLM scanner: provider unavailable (%s); skipping", exc)
            return []

        chunk_lines = int(llm_cfg.get("chunk_lines", 400))
        max_chunks = int(llm_cfg.get("max_chunks", 50))

        findings: List[Finding] = []
        for _target, file_path in self._iter_files(targets):
            file_path = str(file_path)
            try:
                with open(file_path, encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError as exc:
                logger.warning("LLM scanner: cannot read %s: %s", file_path, exc)
                continue

            findings.extend(
                self._scan_file(file_path, content, provider, chunk_lines, max_chunks)
            )
        return findings

    def _scan_file(self, file_path: str, content: str, provider, chunk_lines: int,
                   max_chunks: int) -> List[Finding]:
        lines = content.splitlines()
        if not lines:
            return []

        findings: List[Finding] = []
        n_chunks = 0
        for offset in range(0, len(lines), chunk_lines):
            if n_chunks >= max_chunks:
                break
            chunk = lines[offset:offset + chunk_lines]
            start_line = offset + 1
            end_line = offset + len(chunk)
            code_block = "\n".join(chunk)
            if not code_block.strip():
                continue
            n_chunks += 1

            user_prompt = (
                f"文件名: {file_path}\n"
                f"行号: {start_line}-{end_line}\n"
                f"代码块:\n```\n{code_block}\n```\n"
                f"请分析以上代码并输出 finding JSON 数组。"
            )
            try:
                raw = provider.complete(user_prompt, system=_SYSTEM_PROMPT)
            except (ProviderError, Exception) as exc:  # noqa: BLE001
                logger.warning("LLM scanner: provider call failed on %s: %s", file_path, exc)
                continue

            for item in _extract_json(raw):
                if not isinstance(item, dict):
                    continue
                findings.append(self._build_finding(item, file_path, start_line))
        return findings

    def _build_finding(self, item: Dict[str, Any], file_path: str, base_line: int) -> Finding:
        line = base_line + int(item.get("line", 1) or 1) - 1
        line = max(1, line)
        severity, cvss_score = self._resolve_cvss(item, Severity.MEDIUM)

        references = item.get("references", [])
        if not isinstance(references, list):
            references = []
        tags = item.get("tags", [])
        if not isinstance(tags, list):
            tags = []

        return Finding(
            rule_id=item.get("rule_id") or "llm.generic",
            title=item.get("title") or "LLM 发现的潜在漏洞",
            description=item.get("description") or "",
            severity=severity,
            file_path=file_path,
            line=line,
            column=int(item.get("column", 0) or 0),
            code=item.get("code") or "",
            cwe=item.get("cwe") or "",
            cvss=cvss_score,
            confidence=float(item.get("confidence", 1.0) or 1.0),
            scanner="llm",
            recommendation=item.get("recommendation") or "",
            references=[str(r) for r in references],
            tags=[str(t) for t in tags],
            raw=item,
        )

    def _resolve_cvss(self, item: Dict[str, Any], default: Severity) -> Tuple[Severity, Optional[float]]:
        """Derive ``(severity, cvss_score)`` from a model finding item."""
        severity = _to_severity(item.get("severity", default))
        cvss_value = item.get("cvss")

        score: Optional[float] = None
        if isinstance(cvss_value, str) and cvss_value.startswith("CVSS:"):
            try:
                score = score_cvss31(cvss_value)
                severity = _to_severity(severity_from_cvss(score))
            except Exception:
                score = None
        elif isinstance(cvss_value, (int, float)):
            score = float(cvss_value)
            try:
                severity = _to_severity(severity_from_cvss(score))
            except Exception:
                pass

        return severity, score
