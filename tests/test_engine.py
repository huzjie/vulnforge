"""End-to-end tests for the scan engine in mock mode."""
from __future__ import annotations

from vulnforge.core.engine import ScanEngine
from vulnforge.core.target import TargetCollector
from vulnforge.models import ScanReport


VULNERABLE_PY = """\
import hashlib
import pickle

def process(data):
    password = "hunter2secret"
    digest = hashlib.md5(data).hexdigest()
    obj = pickle.loads(data)
    return password, digest, obj
"""


class TestScanEngine:
    def test_scan_returns_report_with_stats(self, tmp_path, static_config):
        path = tmp_path / "app.py"
        path.write_text(VULNERABLE_PY, encoding="utf-8")

        collector = TargetCollector()
        targets = collector.collect([str(tmp_path)], static_config)
        assert targets, "expected at least one target"

        report = ScanEngine(static_config).scan(targets)

        assert isinstance(report, ScanReport)
        assert report.scan_id
        assert report.targets == targets
        assert isinstance(report.findings, list)

    def test_stats_counts_match_findings(self, tmp_path, static_config):
        path = tmp_path / "app.py"
        path.write_text(VULNERABLE_PY, encoding="utf-8")
        targets = TargetCollector().collect([str(tmp_path)], static_config)
        report = ScanEngine(static_config).scan(targets)

        stats = report.stats
        for key in ("total", "critical", "high", "medium", "low", "info",
                    "by_scanner", "by_cwe", "duration_ms"):
            assert key in stats

        assert stats["total"] == len(report.findings)
        # The sample contains at least a critical (pickle) and a high (password).
        assert stats["critical"] >= 1
        assert stats["high"] >= 1
        assert stats["total"] >= 2

    def test_findings_are_sorted_by_severity(self, tmp_path, static_config):
        path = tmp_path / "app.py"
        path.write_text(VULNERABLE_PY, encoding="utf-8")
        targets = TargetCollector().collect([str(tmp_path)], static_config)
        report = ScanEngine(static_config).scan(targets)

        ranks = [f.severity.rank for f in report.findings]
        assert ranks == sorted(ranks, reverse=True)

    def test_scan_with_no_targets(self, static_config):
        report = ScanEngine(static_config).scan([])
        assert report.stats["total"] == 0
        assert report.findings == []

    def test_disabled_scanners_produce_no_llm_findings(self, tmp_path, static_config):
        # static_config disables llm/fuzz/dependency; only static runs.
        path = tmp_path / "app.py"
        path.write_text(VULNERABLE_PY, encoding="utf-8")
        targets = TargetCollector().collect([str(tmp_path)], static_config)
        report = ScanEngine(static_config).scan(targets)
        assert all(f.scanner == "static" for f in report.findings)
