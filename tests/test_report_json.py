"""Tests for the JSON report renderer."""
from __future__ import annotations

import json

import pytest

from vulnforge.errors import ReportError
from vulnforge.report import render, write


class TestJsonRender:
    def test_renders_valid_json(self, make_report):
        text = render(make_report(), "json")
        doc = json.loads(text)
        assert isinstance(doc, dict)

    def test_contains_meta_stats_findings(self, make_report):
        doc = json.loads(render(make_report(), "json"))
        assert "meta" in doc
        assert "stats" in doc
        assert "findings" in doc

    def test_findings_serialized(self, make_report):
        doc = json.loads(render(make_report(), "json"))
        assert len(doc["findings"]) == 1
        assert doc["findings"][0]["rule_id"] == "test.rule"
        assert doc["findings"][0]["severity"] == "MEDIUM"

    def test_empty_report(self, make_report):
        doc = json.loads(render(make_report(findings=[]), "json"))
        assert doc["findings"] == []
        assert doc["stats"]["total"] == 0


class TestWrite:
    def test_write_returns_path_and_creates_file(self, make_report, tmp_path):
        out = tmp_path / "out" / "report.json"
        result = write(make_report(), "json", str(out))
        assert result == str(out)
        assert out.exists()

    def test_write_content_matches_render(self, make_report, tmp_path):
        report = make_report()
        out = tmp_path / "report.json"
        write(report, "json", str(out))
        assert out.read_text(encoding="utf-8") == render(report, "json")


class TestUnsupportedFormat:
    def test_render_raises(self, make_report):
        with pytest.raises(ReportError):
            render(make_report(), "yaml")
