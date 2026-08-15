"""Tests for the SARIF 2.1.0 report renderer."""
from __future__ import annotations

import json

from vulnforge.report import render, write


class TestSarifRender:
    def test_version_and_runs(self, make_report):
        doc = json.loads(render(make_report(), "sarif"))
        assert doc["version"] == "2.1.0"
        assert "runs" in doc
        assert len(doc["runs"]) == 1

    def test_tool_driver(self, make_report):
        doc = json.loads(render(make_report(), "sarif"))
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "vulnforge"

    def test_results_map_findings(self, make_report):
        doc = json.loads(render(make_report(), "sarif"))
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "test.rule"

    def test_level_mapping(self, make_report, make_finding):
        from vulnforge.models import Severity
        finding = make_finding(severity=Severity.CRITICAL)
        doc = json.loads(render(make_report(findings=[finding]), "sarif"))
        assert doc["runs"][0]["results"][0]["level"] == "error"


class TestSarifWrite:
    def test_write_creates_sarif_file(self, make_report, tmp_path):
        out = tmp_path / "report.sarif"
        write(make_report(), "sarif", str(out))
        assert out.exists()
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"
