"""Tests for target discovery in :mod:`vulnforge.core.target`."""
from __future__ import annotations

from vulnforge.core.target import TargetCollector


def _write(tmp_path, relpath: str, content: str = "") -> str:
    path = tmp_path / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return str(path)


class TestCollectDirectory:
    def test_collects_matching_extensions_only(self, tmp_path):
        _write(tmp_path, "a.py")
        _write(tmp_path, "b.js")
        _write(tmp_path, "notes.txt")
        _write(tmp_path, "sub/c.py")

        collector = TargetCollector()
        targets = collector.collect([str(tmp_path)], config={})

        paths = {t.path for t in targets}
        assert str(tmp_path / "a.py") in paths
        assert str(tmp_path / "b.js") in paths
        assert str(tmp_path / "sub" / "c.py") in paths
        # .txt is not a default scan extension.
        assert str(tmp_path / "notes.txt") not in paths

    def test_language_detection(self, tmp_path):
        _write(tmp_path, "a.py")
        _write(tmp_path, "b.go")
        collector = TargetCollector()
        targets = {t.path: t.language for t in collector.collect([str(tmp_path)], {})}
        assert targets[str(tmp_path / "a.py")] == "python"
        assert targets[str(tmp_path / "b.go")] == "go"

    def test_skips_vendor_and_hidden_dirs(self, tmp_path):
        _write(tmp_path, "src/main.py")
        _write(tmp_path, "node_modules/pkg/index.js")
        _write(tmp_path, ".git/config.py")
        collector = TargetCollector()
        targets = collector.collect([str(tmp_path)], {})
        paths = {t.path for t in targets}
        assert str(tmp_path / "src" / "main.py") in paths
        assert str(tmp_path / "node_modules" / "pkg" / "index.js") not in paths
        assert str(tmp_path / ".git" / "config.py") not in paths

    def test_custom_extensions(self, tmp_path):
        _write(tmp_path, "a.py")
        _write(tmp_path, "b.custom")
        config = {"targets": {"default_extensions": [".custom"]}}
        targets = TargetCollector().collect([str(tmp_path)], config)
        assert {t.path for t in targets} == {str(tmp_path / "b.custom")}


class TestCollectFile:
    def test_single_file(self, tmp_path):
        path = _write(tmp_path, "single.py", "x = 1\n")
        targets = TargetCollector().collect([path], {})
        assert len(targets) == 1
        assert targets[0].path == path
        assert targets[0].kind == "file"
        assert targets[0].size > 0

    def test_ignores_unknown_extension_file(self, tmp_path):
        path = _write(tmp_path, "data.bin", "binary-ish")
        assert TargetCollector().collect([path], {}) == []


class TestDedupe:
    def test_duplicate_paths_collapse(self, tmp_path):
        path = _write(tmp_path, "dup.py", "x = 1\n")
        targets = TargetCollector().collect([path, path, str(tmp_path)], {})
        assert len(targets) == 1

    def test_empty_paths(self):
        assert TargetCollector().collect([], {}) == []
