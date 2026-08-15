"""Tests for configuration loading in :mod:`vulnforge.config`."""
from __future__ import annotations

import pytest

from vulnforge.config import (
    DEFAULT_CONFIG,
    _parse_yaml,
    deep_merge,
    load_config,
)


class TestDefaultConfig:
    def test_top_level_sections(self):
        for section in ("general", "targets", "scanners", "static", "llm",
                        "fuzz", "dependency", "webhook", "api"):
            assert section in DEFAULT_CONFIG

    def test_default_mode_is_mock(self):
        assert DEFAULT_CONFIG["general"]["mode"] == "mock"

    def test_default_provider_is_mock(self):
        assert DEFAULT_CONFIG["llm"]["default_provider"] == "mock"

    def test_static_rules_enabled_by_default(self):
        assert DEFAULT_CONFIG["scanners"]["static"] is True


class TestDeepMerge:
    def test_nested_dicts_merge(self):
        base = {"a": {"x": 1, "y": 2}, "b": 3}
        override = {"a": {"y": 20, "z": 30}}
        merged = deep_merge(base, override)
        assert merged == {"a": {"x": 1, "y": 20, "z": 30}, "b": 3}

    def test_scalars_override(self):
        assert deep_merge({"a": 1}, {"a": 2}) == {"a": 2}

    def test_does_not_mutate_base(self):
        base = {"a": {"x": 1}}
        deep_merge(base, {"a": {"y": 2}})
        assert base == {"a": {"x": 1}}

    def test_new_keys_added(self):
        assert deep_merge({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}


class TestParseYaml:
    def test_nested_structure(self):
        parsed = _parse_yaml("a:\n  b: 1\n  c: hello\n")
        assert parsed == {"a": {"b": 1, "c": "hello"}}

    def test_list(self):
        parsed = _parse_yaml("items:\n  - one\n  - two\n")
        assert parsed == {"items": ["one", "two"]}

    def test_block_list_with_multiple_items(self):
        # The example config uses the space-separated quoted-list form.
        parsed = _parse_yaml('exts:\n  - ".py" ".js" ".ts"\n')
        assert parsed == {"exts": [".py", ".js", ".ts"]}

    def test_quoted_and_bool_and_number(self):
        parsed = _parse_yaml('name: "hello world"\nflag: true\nnum: 3.5\n')
        assert parsed == {"name": "hello world", "flag": True, "num": 3.5}

    def test_comments_stripped(self):
        parsed = _parse_yaml("a: 1  # a comment\nb: 2\n")
        assert parsed == {"a": 1, "b": 2}


class TestLoadConfig:
    def test_returns_dict_with_defaults(self):
        config = load_config()
        assert isinstance(config, dict)
        for section in ("general", "targets", "scanners", "static", "llm"):
            assert section in config

    def test_explicit_path_overrides_defaults(self, tmp_path):
        yaml_path = tmp_path / "custom.yaml"
        yaml_path.write_text(
            "general:\n  mode: live\n  concurrency: 99\n",
            encoding="utf-8",
        )
        config = load_config(str(yaml_path))
        assert config["general"]["mode"] == "live"
        assert config["general"]["concurrency"] == 99
        # Unrelated defaults preserved.
        assert "timeout_seconds" in config["general"]

    def test_explicit_path_merges_nested(self, tmp_path):
        yaml_path = tmp_path / "partial.yaml"
        yaml_path.write_text(
            "llm:\n  temperature: 0.5\n",
            encoding="utf-8",
        )
        config = load_config(str(yaml_path))
        assert config["llm"]["temperature"] == 0.5
        # The nested default_provider key is retained after deep merge.
        assert config["llm"]["default_provider"] == "mock"

    def test_missing_file_raises(self, tmp_path):
        from vulnforge.errors import ConfigError

        missing = tmp_path / "nope.yaml"
        with pytest.raises(ConfigError):
            load_config(str(missing))
