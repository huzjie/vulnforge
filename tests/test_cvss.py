"""Tests for CVSS 3.1 base scoring in :mod:`vulnforge.cvss.calculator`.

All expected scores below are the official FIRST CVSS v3.1 values (verified
against the NVD calculator).
"""
from __future__ import annotations

import pytest

from vulnforge.cvss.calculator import (
    parse_vector,
    score_cvss31,
    severity_from_cvss,
)


class TestScoreCvss31:
    @pytest.mark.parametrize(
        "vector,expected",
        [
            # Classic critical remote RCE.
            ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            # Scope changed -> 10.0 (Log4Shell-style).
            ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            # High attack complexity -> 8.1.
            ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
            # Low impact, user interaction -> 5.4.
            ("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),
            # High privileges required -> 7.2.
            ("AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
            # Low privilege + scope changed -> 9.9.
            ("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
            # No impact -> 0.0.
            ("AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N", 0.0),
        ],
    )
    def test_known_vectors(self, vector, expected):
        assert score_cvss31(vector) == pytest.approx(expected, abs=0.05)

    def test_full_prefix_is_ignored(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert score_cvss31(vector) == pytest.approx(9.8, abs=0.05)

    def test_empty_vector_uses_worst_case_defaults(self):
        # All metrics default to worst-case -> 9.8.
        assert score_cvss31("") == pytest.approx(9.8, abs=0.05)

    def test_partial_vector(self):
        # Omitted C/I/A default to H, omitted S defaults to U.
        assert score_cvss31("AV:N/AC:L/PR:N/UI:N") == pytest.approx(9.8, abs=0.05)

    def test_roundup(self):
        # Ensure the Roundup helper rounds up to one decimal place.
        assert score_cvss31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


class TestParseVector:
    def test_parses_metrics(self):
        parsed = parse_vector("AV:N/AC:L/S:C/C:H/I:N/A:L")
        assert parsed == {"AV": "N", "AC": "L", "S": "C", "C": "H", "I": "N", "A": "L"}

    def test_ignores_prefix_and_unknown(self):
        parsed = parse_vector("CVSS:3.1/AV:N/FOO:bar/AC:H")
        assert parsed == {"AV": "N", "AC": "H"}

    def test_empty_returns_empty(self):
        assert parse_vector("") == {}
        assert parse_vector(None) == {}


class TestSeverityFromCvss:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (None, "none"),
            (0.0, "none"),
            (0.1, "low"),
            (3.9, "low"),
            (4.0, "medium"),
            (6.9, "medium"),
            (7.0, "high"),
            (8.9, "high"),
            (9.0, "critical"),
            (9.8, "critical"),
            (10.0, "critical"),
        ],
    )
    def test_mapping(self, score, expected):
        assert severity_from_cvss(score) == expected
