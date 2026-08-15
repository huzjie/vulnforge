"""Regex matcher that turns rule hits into Finding objects."""

from __future__ import annotations

import re
from typing import List

from ...models import Finding, Severity
from .rule import StaticRule

_SNIPPET_MAX = 200


def _snippet(text: str) -> str:
    """Trim and truncate a line for use as a code snippet."""
    stripped = text.strip()
    if len(stripped) <= _SNIPPET_MAX:
        return stripped
    return stripped[:_SNIPPET_MAX] + "..."


class StaticMatcher:
    """Matches a single :class:`StaticRule` against file content."""

    def match(self, path: str, content: str, rule: StaticRule) -> List[Finding]:
        """Apply a rule to file content, returning one Finding per hit.

        Args:
            path: File path (used for reporting and extension filtering).
            content: Full file content as text.
            rule: The rule to apply.

        Returns:
            A list of :class:`Finding` objects for each regex match.
        """
        findings: List[Finding] = []
        severity = Severity.from_str(rule.severity)

        if rule.extensions is not None:
            import os

            ext = os.path.splitext(path)[1].lower()
            if ext not in {e.lower() for e in rule.extensions}:
                return findings

        if rule.multiline:
            findings.extend(self._match_multiline(path, content, rule, severity))
        else:
            findings.extend(self._match_lines(path, content, rule, severity))
        return findings

    def _match_lines(
        self, path: str, content: str, rule: StaticRule, severity: Severity
    ) -> List[Finding]:
        """Line-by-line matching for single-line rules."""
        findings: List[Finding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern in rule.patterns:
                match = re.search(pattern, line, rule.flags)
                if not match:
                    continue
                findings.append(self._build_finding(
                    rule, severity, path, line_no, _snippet(line),
                ))
        return findings

    def _match_multiline(
        self, path: str, content: str, rule: StaticRule, severity: Severity
    ) -> List[Finding]:
        """Full-content matching for multiline rules."""
        findings: List[Finding] = []
        for pattern in rule.patterns:
            for match in re.finditer(pattern, content, rule.flags):
                line_no = content.count("\n", 0, match.start()) + 1
                snippet = _snippet(match.group(0))
                findings.append(self._build_finding(
                    rule, severity, path, line_no, snippet,
                ))
        return findings

    @staticmethod
    def _build_finding(
        rule: StaticRule,
        severity: Severity,
        path: str,
        line_no: int,
        snippet: str,
    ) -> Finding:
        """Construct a Finding from a rule hit."""
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            description=rule.description,
            severity=severity,
            file_path=path,
            line=line_no,
            code=snippet,
            cwe=rule.cwe,
            confidence=1.0,
            scanner="static",
            recommendation=rule.recommendation,
            tags=[rule.id.split("-")[0]] if "-" in rule.id else [],
        )


__all__ = ["StaticMatcher"]
