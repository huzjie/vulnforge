"""Tests for the dependency / SBOM scanner.

Focuses on offline ``requirements.txt`` parsing and SBOM finding emission.
"""
from __future__ import annotations

from vulnforge.models import Severity, Target
from vulnforge.scanners.dependency import DependencyScanner


REQUIREMENTS = """\
requests==2.31.0
flask>=2.0.0
# a comment line
-numpy
"""


def _scan_requirements(tmp_path, content: str = REQUIREMENTS):
    path = tmp_path / "requirements.txt"
    path.write_text(content, encoding="utf-8")
    target = Target(path=str(path), kind="file", language="")
    config = {"dependency": {"offline": True}}
    return DependencyScanner().scan([target], config)


class TestDependencyScanner:
    def test_parses_requirements(self, tmp_path):
        findings = _scan_requirements(tmp_path)
        packages = {f.raw.get("package") for f in findings}
        assert "requests" in packages
        assert "flask" in packages

    def test_skips_comments_and_flags(self, tmp_path):
        findings = _scan_requirements(tmp_path)
        packages = {f.raw.get("package") for f in findings}
        assert "numpy" not in packages

    def test_sbom_finding_shape(self, tmp_path):
        findings = _scan_requirements(tmp_path)
        assert findings
        for finding in findings:
            assert finding.rule_id == "dependency.package"
            assert finding.scanner == "dependency"
            assert finding.severity is Severity.INFO
            assert "purl" in finding.raw
            assert finding.raw["purl"].startswith("pkg:pypi/")

    def test_offline_flag_sets_pending(self, tmp_path):
        findings = _scan_requirements(tmp_path)
        assert all(f.raw.get("pending_osv") is True for f in findings)

    def test_non_manifest_file_ignored(self, tmp_path):
        path = tmp_path / "README.md"
        path.write_text("# no deps here", encoding="utf-8")
        target = Target(path=str(path), kind="file", language="")
        findings = DependencyScanner().scan([target], {"dependency": {"offline": True}})
        assert findings == []

    def test_empty_manifest_ignored(self, tmp_path):
        findings = _scan_requirements(tmp_path, "# nothing but comments\n")
        assert findings == []
