"""Tests for the CycloneDX 1.5 SBOM renderer."""
from __future__ import annotations

import json

from vulnforge.models import Finding, ScanReport, Severity, Target
from vulnforge.report import render, write


def _sbom_report() -> ScanReport:
    finding = Finding(
        rule_id="dependency.package",
        title="依赖: requests@2.31.0 (PyPI)",
        description="SBOM entry",
        severity=Severity.INFO,
        file_path="requirements.txt",
        line=0,
        scanner="dependency",
        tags=["sbom", "dependency"],
        raw={
            "package": "requests",
            "version": "2.31.0",
            "ecosystem": "PyPI",
            "purl": "pkg:pypi/requests@2.31.0",
        },
    )
    return ScanReport(
        scan_id="s",
        created_at="2026-01-01T00:00:00Z",
        targets=[Target(path="requirements.txt", kind="file")],
        findings=[finding],
        stats={},
    )


class TestCycloneDxRender:
    def test_bom_format(self):
        doc = json.loads(render(_sbom_report(), "cyclonedx"))
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"

    def test_components_from_sbom_findings(self):
        doc = json.loads(render(_sbom_report(), "cyclonedx"))
        components = doc.get("components", [])
        assert len(components) == 1
        assert components[0]["name"] == "requests"
        assert components[0]["version"] == "2.31.0"
        assert components[0]["purl"] == "pkg:pypi/requests@2.31.0"

    def test_sbom_alias(self):
        doc = json.loads(render(_sbom_report(), "sbom"))
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"

    def test_ignores_non_sbom_findings(self, make_report):
        # A report with only a static finding -> no SBOM components.
        doc = json.loads(render(make_report(), "cyclonedx"))
        assert doc.get("components", []) == []


class TestCycloneDxWrite:
    def test_write_creates_file(self, tmp_path):
        out = tmp_path / "sbom.json"
        write(_sbom_report(), "cyclonedx", str(out))
        assert out.exists()
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["bomFormat"] == "CycloneDX"
