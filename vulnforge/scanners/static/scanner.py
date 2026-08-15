"""StaticScanner: rule-based static analysis over source files."""

from __future__ import annotations

import os
from typing import List

from ...models import Finding, Target
from ..base import BaseScanner
from ..registry import register
from .matcher import StaticMatcher
from .rule import StaticRule
from .rules import RULES


@register
class StaticScanner(BaseScanner):
    """Scans source files with the bundled static rules."""

    name = "static"

    def __init__(self) -> None:
        """Initialize the scanner with a matcher and the bundled rules."""
        self.matcher = StaticMatcher()
        self.rules: List[StaticRule] = RULES

    def scan(self, targets: List[Target], config: dict) -> List[Finding]:
        """Run all static rules over every file in the targets.

        Args:
            targets: Targets to scan.
            config: Merged configuration dict.

        Returns:
            Aggregated list of :class:`Finding` objects.
        """
        findings: List[Finding] = []
        for _, file_path in self._iter_files(targets):
            ext = os.path.splitext(file_path)[1].lower()
            content = self._read_file(file_path)
            if content is None:
                continue
            for rule in self.rules:
                if rule.extensions is not None and ext not in {
                    e.lower() for e in rule.extensions
                }:
                    continue
                findings.extend(self.matcher.match(file_path, content, rule))
        return findings

    @staticmethod
    def _read_file(path: str) -> "str | None":
        """Read a file as UTF-8 text, returning ``None`` on failure."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except (OSError, UnicodeDecodeError):
            return None


__all__ = ["StaticScanner"]
