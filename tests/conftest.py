"""Shared pytest fixtures for the vulnforge test suite.

All fixtures are fully offline and deterministic: no network, no API keys, no
external services.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the repository root (which contains the ``vulnforge`` package) is
# importable regardless of pytest's rootdir/import-mode configuration.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnforge.models import (  # noqa: E402
    Finding,
    ScanReport,
    Severity,
    Target,
)


@pytest.fixture
def make_finding():
    """Return a factory that builds a :class:`Finding` with sensible defaults."""

    def _make(**overrides) -> Finding:
        defaults = dict(
            rule_id="test.rule",
            title="Test finding",
            description="A synthetic finding used in tests.",
            severity=Severity.MEDIUM,
            file_path="src/app.py",
            line=10,
        )
        defaults.update(overrides)
        return Finding(**defaults)

    return _make


@pytest.fixture
def make_target():
    """Return a factory that builds a :class:`Target`."""

    def _make(
        path: str = "src/app.py",
        kind: str = "file",
        language: str = "python",
        size: int = 100,
    ) -> Target:
        return Target(path=path, kind=kind, language=language, size=size)

    return _make


@pytest.fixture
def mock_config():
    """Return a fully-merged offline ``mock`` configuration dict."""
    from vulnforge.config import load_config

    return load_config()


@pytest.fixture
def static_config():
    """Return a minimal config that enables only the static scanner.

    Kept deliberately small so scanner/engine tests are deterministic and
    independent of ambient ``config.yaml`` files.
    """
    return {
        "scanners": {
            "static": True,
            "llm": False,
            "fuzz": False,
            "dependency": False,
            "secrets": True,
        },
        "static": {"min_severity": "low"},
        "general": {"output_dir": "./results"},
    }


@pytest.fixture
def make_report(make_finding, make_target):
    """Return a factory that builds a :class:`ScanReport` with one finding."""

    def _make(**overrides) -> ScanReport:
        finding = make_finding()
        target = make_target()
        defaults = dict(
            scan_id="scan-0001",
            created_at="2026-01-01T00:00:00+00:00",
            targets=[target],
            findings=[finding],
            stats={"total": 1, "critical": 0, "high": 0, "medium": 1,
                   "low": 0, "info": 0},
        )
        defaults.update(overrides)
        return ScanReport(**defaults)

    return _make


@pytest.fixture
def tmp_file(tmp_path):
    """Write text to a temp file and return its absolute path string."""

    def _write(content: str, name: str = "sample.py") -> str:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return str(path)

    return _write
