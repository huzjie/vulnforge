"""Tests for the :class:`Severity` enum (ordering, coercion, thresholds)."""
from __future__ import annotations

import pytest

from vulnforge.models import Severity


class TestSeverityValues:
    def test_string_values(self):
        assert Severity.INFO.value == "info"
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_rank_monotonic(self):
        ranks = [s.rank for s in Severity]
        assert ranks == [0, 1, 2, 3, 4]


class TestSeverityFromScore:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0.0, Severity.INFO),
            (0.9, Severity.LOW),
            (1.0, Severity.LOW),
            (3.9, Severity.LOW),
            (4.0, Severity.MEDIUM),
            (6.9, Severity.MEDIUM),
            (7.0, Severity.HIGH),
            (8.9, Severity.HIGH),
            (9.0, Severity.CRITICAL),
            (10.0, Severity.CRITICAL),
        ],
    )
    def test_boundaries(self, score, expected):
        assert Severity.from_score(score) is expected


class TestSeverityFromStr:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("info", Severity.INFO),
            ("low", Severity.LOW),
            ("medium", Severity.MEDIUM),
            ("high", Severity.HIGH),
            ("critical", Severity.CRITICAL),
            ("  HIGH  ", Severity.HIGH),
            ("Critical", Severity.CRITICAL),
        ],
    )
    def test_valid(self, raw, expected):
        assert Severity.from_str(raw) is expected

    @pytest.mark.parametrize("raw", ["", "bogus", "CRIT", None])
    def test_invalid_falls_back_to_info(self, raw):
        assert Severity.from_str(raw) is Severity.INFO


class TestSeverityOrdering:
    def test_ordering_chain(self):
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_sort_descending(self):
        items = [Severity.MEDIUM, Severity.CRITICAL, Severity.INFO, Severity.HIGH]
        assert sorted(items, reverse=True) == [
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO,
        ]
