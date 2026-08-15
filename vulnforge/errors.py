"""Exception hierarchy for vulnforge."""

from __future__ import annotations


class VulnforgeError(Exception):
    """Base class for all vulnforge-specific errors."""


class ConfigError(VulnforgeError):
    """Raised when configuration loading or validation fails."""


class ScannerError(VulnforgeError):
    """Raised when a scanner fails to execute."""


class ProviderError(VulnforgeError):
    """Raised when an LLM / external provider call fails."""


class FuzzTimeoutError(VulnforgeError):
    """Raised when a fuzzing run exceeds its configured time budget."""


class ReportError(VulnforgeError):
    """Raised when report generation or serialization fails."""


__all__ = [
    "VulnforgeError",
    "ConfigError",
    "ScannerError",
    "ProviderError",
    "FuzzTimeoutError",
    "ReportError",
]
