"""Tests for the mock LLM provider and the LLM reasoning scanner's parsing."""
from __future__ import annotations

import json

from vulnforge.llm import MockProvider, get_provider, list_providers
from vulnforge.models import Severity
from vulnforge.scanners.llm import (
    LLMReasoningScanner,
    _extract_json,
    _to_severity,
)


class TestMockProvider:
    def test_deterministic_output(self):
        provider = MockProvider({})
        first = provider.complete("eval(user_input)")
        second = provider.complete("eval(user_input)")
        assert first == second

    def test_eval_detected(self):
        provider = MockProvider({})
        out = json.loads(provider.complete("code = eval(user_input)"))
        assert isinstance(out, list)
        assert any(f["rule_id"] == "mock.eval-rce" for f in out)

    def test_pickle_detected(self):
        provider = MockProvider({})
        out = json.loads(provider.complete("obj = pickle.loads(data)"))
        assert any(f["rule_id"] == "mock.pickle-deserialization" for f in out)

    def test_clean_prompt_returns_empty(self):
        provider = MockProvider({})
        out = json.loads(provider.complete("def add(a, b): return a + b"))
        assert out == []

    def test_returns_json_string(self):
        provider = MockProvider({})
        text = provider.complete("eval(1)")
        json.loads(text)  # must not raise


class TestProviderRegistry:
    def test_list_providers_includes_mock(self):
        assert "mock" in list_providers()

    def test_get_provider_mock(self):
        provider = get_provider("mock", {})
        assert isinstance(provider, MockProvider)

    def test_get_provider_unknown_raises(self):
        import pytest
        with pytest.raises(ValueError):
            get_provider("does-not-exist", {})


class TestExtractJson:
    def test_plain_array(self):
        assert _extract_json('[{"rule_id": "x"}]') == [{"rule_id": "x"}]

    def test_fenced_array(self):
        text = '```json\n[{"a": 1}]\n```'
        assert _extract_json(text) == [{"a": 1}]

    def test_wrapped_in_prose(self):
        text = 'Here you go: [{"a": 1}] hope it helps'
        assert _extract_json(text) == [{"a": 1}]

    def test_garbage_returns_empty(self):
        assert _extract_json("not json at all") == []

    def test_empty_returns_empty(self):
        assert _extract_json("") == []
        assert _extract_json(None) == []


class TestToSeverity:
    def test_known_values(self):
        assert _to_severity("high") is Severity.HIGH
        assert _to_severity("critical") is Severity.CRITICAL

    def test_unknown_falls_back_to_medium(self):
        assert _to_severity("bogus") is Severity.MEDIUM
        assert _to_severity(None) is Severity.MEDIUM

    def test_enum_passthrough(self):
        assert _to_severity(Severity.LOW) is Severity.LOW


class TestLLMReasoningScanner:
    def test_build_finding_maps_fields(self):
        scanner = LLMReasoningScanner()
        item = {
            "rule_id": "r",
            "title": "t",
            "description": "d",
            "severity": "critical",
            "cwe": "CWE-89",
            "line": 2,
        }
        finding = scanner._build_finding(item, "f.py", base_line=10)
        assert finding.rule_id == "r"
        assert finding.severity is Severity.CRITICAL
        assert finding.file_path == "f.py"
        assert finding.line == 11  # base_line + line - 1
        assert finding.scanner == "llm"
        assert finding.cwe == "CWE-89"

    def test_build_finding_defaults(self):
        scanner = LLMReasoningScanner()
        finding = scanner._build_finding({}, "f.py", base_line=1)
        assert finding.rule_id == "llm.generic"
        assert finding.severity is Severity.MEDIUM
        assert finding.line == 1
