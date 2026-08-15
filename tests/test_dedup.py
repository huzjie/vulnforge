"""Tests for finding de-duplication in :mod:`vulnforge.core.dedup`."""
from __future__ import annotations

from vulnforge.core.dedup import dedupe
from vulnforge.core.severity import sort_findings
from vulnforge.models import Finding, Severity


def _finding(rule_id="r", severity=Severity.MEDIUM, line=1,
             file_path="a.py", confidence=1.0) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="t",
        description="d",
        severity=severity,
        file_path=file_path,
        line=line,
        confidence=confidence,
    )


class TestDedupe:
    def test_same_key_keeps_highest_severity(self):
        findings = [
            _finding(severity=Severity.LOW),
            _finding(severity=Severity.HIGH),
            _finding(severity=Severity.MEDIUM),
        ]
        unique = dedupe(findings)
        assert len(unique) == 1
        assert unique[0].severity is Severity.HIGH

    def test_severity_tie_keeps_highest_confidence(self):
        findings = [
            _finding(severity=Severity.HIGH, confidence=0.5),
            _finding(severity=Severity.HIGH, confidence=0.9),
        ]
        unique = dedupe(findings)
        assert len(unique) == 1
        assert unique[0].confidence == 0.9

    def test_different_line_kept_separate(self):
        findings = [
            _finding(line=1),
            _finding(line=2),
        ]
        assert len(dedupe(findings)) == 2

    def test_different_rule_kept_separate(self):
        findings = [
            _finding(rule_id="a"),
            _finding(rule_id="b"),
        ]
        assert len(dedupe(findings)) == 2

    def test_empty(self):
        assert dedupe([]) == []


class TestSortFindings:
    def test_sorts_by_severity_desc(self):
        findings = [
            _finding(severity=Severity.LOW),
            _finding(severity=Severity.CRITICAL),
            _finding(severity=Severity.HIGH),
        ]
        ordered = sort_findings(findings)
        assert [f.severity for f in ordered] == [
            Severity.CRITICAL, Severity.HIGH, Severity.LOW,
        ]

    def test_tie_breaks_by_location(self):
        findings = [
            _finding(severity=Severity.HIGH, file_path="b.py", line=1),
            _finding(severity=Severity.HIGH, file_path="a.py", line=2),
            _finding(severity=Severity.HIGH, file_path="a.py", line=1),
        ]
        ordered = sort_findings(findings)
        assert [(f.file_path, f.line) for f in ordered] == [
            ("a.py", 1), ("a.py", 2), ("b.py", 1),
        ]
