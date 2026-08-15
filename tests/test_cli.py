"""Tests for the CLI entrypoint :func:`vulnforge.cli.main.main`."""
from __future__ import annotations

from vulnforge.cli.main import main


class TestCliExitCodes:
    def test_no_args_prints_help_and_returns_zero(self, capsys):
        assert main([]) == 0
        captured = capsys.readouterr()
        assert "vulnforge" in captured.out

    def test_version_returns_zero(self, capsys):
        assert main(["version"]) == 0
        captured = capsys.readouterr()
        assert captured.out.strip() == "1.0.0"

    def test_doctor_returns_zero(self, capsys):
        assert main(["doctor"]) == 0
        captured = capsys.readouterr()
        assert "检查项" in captured.out

    def test_rules_returns_zero(self, capsys):
        assert main(["rules"]) == 0
        captured = capsys.readouterr()
        # The rules command prints a table with at least one rule row.
        assert "rule_id" in captured.out or "共" in captured.out

    def test_providers_returns_zero(self, capsys):
        assert main(["providers"]) == 0

    def test_scanners_returns_zero(self, capsys):
        assert main(["scanners"]) == 0
