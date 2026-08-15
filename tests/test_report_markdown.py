"""Tests for the Markdown report renderer."""
from __future__ import annotations

from vulnforge.report import render, write


class TestMarkdownRender:
    def test_returns_markdown_string(self, make_report):
        text = render(make_report(), "markdown")
        assert isinstance(text, str)
        assert text

    def test_has_heading_and_overview(self, make_report):
        text = render(make_report(), "markdown")
        assert "# vulnforge" in text
        assert "## 概览" in text

    def test_mentions_finding(self, make_report):
        text = render(make_report(), "markdown")
        assert "test.rule" in text

    def test_md_alias(self, make_report):
        assert render(make_report(), "md") == render(make_report(), "markdown")

    def test_empty_report(self, make_report):
        text = render(make_report(findings=[]), "markdown")
        assert "共发现 **0** 个问题" in text


class TestMarkdownWrite:
    def test_write_creates_file(self, make_report, tmp_path):
        out = tmp_path / "report.md"
        write(make_report(), "markdown", str(out))
        assert out.exists()
        assert out.read_text(encoding="utf-8").startswith("# vulnforge")
