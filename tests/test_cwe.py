"""Tests for the CWE lookup table in :mod:`vulnforge.cwe`."""
from __future__ import annotations

from vulnforge.cwe import CWE, cwe_name


class TestCweLookup:
    def test_known_ids(self):
        assert cwe_name("CWE-89") == "SQL Injection"
        assert cwe_name("CWE-79") == "Cross-site Scripting (XSS)"
        assert cwe_name("CWE-22") == "Path Traversal"
        assert cwe_name("CWE-798") == "Use of Hard-coded Credentials"

    def test_without_prefix(self):
        assert cwe_name("89") == "SQL Injection"
        assert cwe_name("918") == "Server-Side Request Forgery (SSRF)"

    def test_case_insensitive(self):
        assert cwe_name("cwe-89") == "SQL Injection"
        assert cwe_name("CWE-502") == "Deserialization of Untrusted Data"

    def test_unknown_returns_input(self):
        assert cwe_name("CWE-9999") == "CWE-9999"
        assert cwe_name("not-a-cwe") == "not-a-cwe"

    def test_empty_returns_empty(self):
        assert cwe_name("") == ""
        assert cwe_name(None) is None


class TestCweTable:
    def test_table_non_empty(self):
        assert len(CWE) >= 20

    def test_key_subset(self):
        for key in ("CWE-22", "CWE-77", "CWE-79", "CWE-89", "CWE-502",
                    "CWE-798", "CWE-918"):
            assert key in CWE

    def test_values_non_empty(self):
        for name in CWE.values():
            assert isinstance(name, str) and name
