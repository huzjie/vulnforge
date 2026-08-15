"""Scan orchestration engine.

``ScanEngine`` instantiates the enabled scanners (from the scanner registry),
runs them over a list of targets, and produces a fully aggregated
:class:`~vulnforge.models.ScanReport` with de-duplicated, sorted findings and
summary statistics.  It runs completely offline in ``mock`` mode.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..logging import get_logger
from ..models import Finding, ScanReport, Target
from .dedup import dedupe
from .severity import sort_findings

# Imported lazily via scanners package so the static scanner auto-registers.
from ..scanners import create_scanners  # noqa: E402


class ScanEngine:
    """Runs enabled scanners and aggregates results into a ScanReport."""

    def __init__(self, config: dict):
        """Initialize the engine with a configuration dict.

        Args:
            config: The merged configuration (see :func:`vulnforge.load_config`).
        """
        self.config: Dict[str, Any] = config
        self.logger = get_logger("vulnforge.engine")

    def scan(self, targets: List[Target]) -> ScanReport:
        """Scan the given targets and produce an aggregated report.

        Args:
            targets: List of :class:`Target` objects to scan.

        Returns:
            A :class:`ScanReport` with de-duplicated, sorted findings and stats.
        """
        started = time.perf_counter()

        enabled = self.config.get("scanners") or {}
        scanners = create_scanners(enabled)

        raw_findings: List[Finding] = []
        by_scanner: Dict[str, int] = {}
        for scanner in scanners:
            try:
                findings = scanner.scan(targets, self.config)
            except Exception as exc:  # noqa: BLE001 - keep other scanners alive
                self.logger.error("scanner %s failed: %s", scanner.name, exc)
                findings = []
            raw_findings.extend(findings)
            by_scanner[scanner.name] = len(findings)

        findings = sort_findings(dedupe(raw_findings))
        stats = self._build_stats(findings, by_scanner)
        stats["duration_ms"] = int((time.perf_counter() - started) * 1000)

        return ScanReport(
            scan_id=uuid.uuid4().hex,
            created_at=datetime.now(timezone.utc).isoformat(),
            targets=targets,
            findings=findings,
            stats=stats,
            config=self.config,
        )

    @staticmethod
    def _build_stats(
        findings: List[Finding], by_scanner: Dict[str, int]
    ) -> Dict[str, Any]:
        """Build the summary statistics dict."""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        by_cwe: Dict[str, int] = {}
        for finding in findings:
            severity_counts[finding.severity.value] = (
                severity_counts.get(finding.severity.value, 0) + 1
            )
            if finding.cwe:
                by_cwe[finding.cwe] = by_cwe.get(finding.cwe, 0) + 1

        stats: Dict[str, Any] = {
            "total": len(findings),
            **severity_counts,
            "by_scanner": by_scanner,
            "by_cwe": by_cwe,
        }
        return stats


__all__ = ["ScanEngine"]
