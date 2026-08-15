"""Core execution engine for vulnforge."""

from .target import TargetCollector
from .scheduler import run_parallel
from .dedup import dedupe
from .severity import sort_findings, filter_by_threshold
from .engine import ScanEngine

__all__ = [
    "TargetCollector",
    "run_parallel",
    "dedupe",
    "sort_findings",
    "filter_by_threshold",
    "ScanEngine",
]
