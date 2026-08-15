"""Tests for the core data models in :mod:`vulnforge.models`."""
from __future__ import annotations

import pytest

from vulnforge.models import (
    Finding,
    ScanReport,
    ScanResult,
    Severity,
    Target,
)


class TestSeverity:
    def test_enum_values(self):
        assert [s.value for s in Severity] == [
            "info", "low", "medium", "high", "critical",
        ]

    def test_rank_ordering(self):
        assert Severity.INFO.rank == 0
        assert Severity.LOW.rank == 1
        assert Severity.MEDIUM.rank == 2
        assert Severity.HIGH.rank == 3
        assert Severity.CRITICAL.rank == 4

    def test_from_str(self):
        assert Severity.from_str("high") is Severity.HIGH
        assert Severity.from_str("CRITICAL") is Severity.CRITICAL
        assert Severity.from_str("unknown") is Severity.INFO
        assert Severity.from_str(None) is Severity.INFO

    def test_from_score(self):
        assert Severity.from_score(0.0) is Severity.INFO
        assert Severity.from_score(3.9) is Severity.LOW
        assert Severity.from_score(6.9) is Severity.MEDIUM
        assert Severity.from_score(8.9) is Severity.HIGH
        assert Severity.from_score(9.0) is Severity.CRITICAL

    def test_comparisons(self):
        assert Severity.LOW < Severity.HIGH
        assert Severity.CRITICAL > Severity.MEDIUM
        assert Severity.MEDIUM >= Severity.MEDIUM
        assert Severity.INFO <= Severity.LOW
        assert Severity.HIGH != Severity.CRITICAL

    def test_sortable(self):
        ordered = sorted(
            [Severity.CRITICAL, Severity.INFO, Severity.HIGH, Severity.LOW]
        )
        assert ordered == [
            Severity.INFO, Severity.LOW, Severity.HIGH, Severity.CRITICAL,
        ]


class TestFinding:
    def test_required_fields(self):
        finding = Finding(
            rule_id="rule-1",
            title="t",
            description="d",
            severity=Severity.HIGH,
            file_path="a.py",
            line=3,
        )
        assert finding.rule_id == "rule-1"
        assert finding.severity is Severity.HIGH
        assert finding.line == 3

    def test_defaults(self):
        finding = Finding(
            rule_id="r", title="t", description="d",
            severity=Severity.LOW, file_path="f.py", line=1,
        )
        assert finding.column == 0
        assert finding.code == ""
        assert finding.cwe == ""
        assert finding.cvss is None
        assert finding.confidence == 1.0
        assert finding.scanner == "static"
        assert finding.recommendation == ""
        assert finding.references == []
        assert finding.tags == []
        assert finding.raw == {}

    def test_dataclass_equality(self):
        args = dict(
            rule_id="r", title="t", description="d",
            severity=Severity.MEDIUM, file_path="f.py", line=2,
        )
        assert Finding(**args) == Finding(**args)


class TestTarget:
    def test_construction(self):
        target = Target(path="/repo/a.py", kind="file", language="python", size=42)
        assert target.path == "/repo/a.py"
        assert target.kind == "file"
        assert target.language == "python"
        assert target.size == 42

    def test_defaults(self):
        target = Target(path="b.py", kind="directory")
        assert target.language == ""
        assert target.size == 0


class TestScanResult:
    def test_construction(self):
        target = Target(path="a.py", kind="file")
        finding = Finding(
            rule_id="r", title="t", description="d",
            severity=Severity.LOW, file_path="a.py", line=1,
        )
        result = ScanResult(target=target, findings=[finding], duration_ms=5)
        assert result.target is target
        assert result.findings == [finding]
        assert result.duration_ms == 5
        assert result.error == ""


class TestScanReport:
    def test_construction(self):
        report = ScanReport(
            scan_id="s1",
            created_at="2026-01-01T00:00:00Z",
            targets=[],
            findings=[],
        )
        assert report.scan_id == "s1"
        assert report.stats == {}
        assert report.config == {}

    def test_defaults(self):
        report = ScanReport(scan_id="s", created_at="c", targets=[], findings=[])
        assert report.stats == {}
        assert report.config == {}
