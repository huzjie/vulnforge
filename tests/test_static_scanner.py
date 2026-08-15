"""Tests for the static scanner and its bundled rules.

Each case writes a deliberately vulnerable snippet to a temp file and asserts
that the :class:`StaticScanner` flags the expected rule ids.
"""
from __future__ import annotations

from vulnforge.models import Target
from vulnforge.scanners.static.scanner import StaticScanner


def _scan_file(tmp_path, content: str, name: str = "sample.py"):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    target = Target(path=str(path), kind="file", language="python")
    return StaticScanner().scan([target], config={})


def _rule_ids(findings) -> set:
    return {f.rule_id for f in findings}


class TestStaticScanner:
    def test_sql_injection(self, tmp_path):
        content = (
            'def f(uid):\n'
            '    query = "SELECT * FROM users WHERE id = " + uid\n'
            '    return query\n'
        )
        findings = _scan_file(tmp_path, content)
        ids = _rule_ids(findings)
        assert "sql-query-concat" in ids
        # All findings are attributed to the static scanner.
        assert all(f.scanner == "static" for f in findings)
        assert all(f.cwe == "CWE-89" for f in findings if "sql" in f.rule_id)

    def test_command_injection(self, tmp_path):
        content = 'import os\n\ndef g(host):\n    os.system("ping -c 1 " + host)\n'
        findings = _scan_file(tmp_path, content)
        assert "cmd-os-system" in _rule_ids(findings)

    def test_weak_crypto(self, tmp_path):
        content = (
            'import hashlib\n'
            'def h(pw):\n'
            '    return hashlib.md5(pw.encode()).hexdigest()\n'
        )
        findings = _scan_file(tmp_path, content)
        assert "crypto-md5" in _rule_ids(findings)

    def test_deserialization(self, tmp_path):
        content = 'import pickle\n\ndef d(b):\n    return pickle.loads(b)\n'
        findings = _scan_file(tmp_path, content)
        assert "deser-pickle-load" in _rule_ids(findings)

    def test_ssrf(self, tmp_path):
        content = 'import requests\n\ndef f(url):\n    return requests.get(url)\n'
        findings = _scan_file(tmp_path, content)
        assert "ssrf-requests-get" in _rule_ids(findings)

    def test_path_traversal(self, tmp_path):
        content = (
            'def f(filename):\n'
            '    with open("uploads/" + filename, "r") as fh:\n'
            '        return fh.read()\n'
        )
        findings = _scan_file(tmp_path, content)
        assert "path-traversal-open-concat" in _rule_ids(findings)

    def test_xss_in_javascript(self, tmp_path):
        content = (
            "function render(name) {\n"
            "  document.getElementById('out').innerHTML = '<b>' + name + '</b>';\n"
            "}\n"
        )
        findings = _scan_file(tmp_path, content, name="app.js")
        assert "xss-innerhtml" in _rule_ids(findings)

    def test_clean_file_yields_no_findings(self, tmp_path):
        content = (
            "def add(a, b):\n"
            "    return a + b\n"
            "\n"
            "def greet(name):\n"
            "    return f'hello {name}'\n"
        )
        findings = _scan_file(tmp_path, content)
        assert findings == []

    def test_findings_carry_severity_and_location(self, tmp_path):
        content = 'import os\n\ndef g(host):\n    os.system("ping " + host)\n'
        findings = _scan_file(tmp_path, content)
        assert findings
        finding = findings[0]
        assert finding.severity.value == "critical"
        assert finding.line > 0
        assert finding.file_path.endswith("sample.py")
