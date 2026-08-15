"""vulnforge: AI-powered autonomous vulnerability research & security audit.

This package exposes the stable public API used by the rest of the platform.
"""

from __future__ import annotations

from ._version import __version__
from .cwe import CWE, cwe_name
from .config import load_config
from .errors import (
    VulnforgeError,
    ConfigError,
    ScannerError,
    ProviderError,
    FuzzTimeoutError,
    ReportError,
)
from .models import (
    Severity,
    Finding,
    Target,
    ScanResult,
    ScanReport,
)

__all__ = [
    "__version__",
    "Severity",
    "Finding",
    "Target",
    "ScanResult",
    "ScanReport",
    "CWE",
    "cwe_name",
    "load_config",
    "VulnforgeError",
    "ConfigError",
    "ScannerError",
    "ProviderError",
    "FuzzTimeoutError",
    "ReportError",
]
