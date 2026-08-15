"""Tests for the hardcoded-secrets detection rules (CWE-798)."""
from __future__ import annotations

from vulnforge.models import Target
from vulnforge.scanners.static.rules.secrets import RULES
from vulnforge.scanners.static.scanner import StaticScanner


class TestSecretsRuleDefinitions:
    def test_rules_non_empty(self):
        assert len(RULES) >= 10

    def test_all_rules_are_cwe_798(self):
        for rule in RULES:
            assert rule.cwe == "CWE-798"

    def test_rule_ids_unique(self):
        ids = [rule.id for rule in RULES]
        assert len(ids) == len(set(ids))


class TestSecretsDetection:
    def _scan(self, tmp_path, content: str):
        path = tmp_path / "secrets.py"
        path.write_text(content, encoding="utf-8")
        target = Target(path=str(path), kind="file", language="python")
        return StaticScanner().scan([target], config={})

    def test_aws_access_key(self, tmp_path):
        findings = self._scan(
            tmp_path,
            'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n',
        )
        assert "secrets-aws-access-key" in {f.rule_id for f in findings}

    def test_password_assignment(self, tmp_path):
        findings = self._scan(
            tmp_path,
            'password = "P@ssw0rd!2024"\n',
        )
        ids = {f.rule_id for f in findings}
        assert "secrets-password-assignment" in ids

    def test_github_token(self, tmp_path):
        findings = self._scan(
            tmp_path,
            'TOKEN = "ghp_' + "a" * 36 + '"\n',
        )
        assert "secrets-github-token" in {f.rule_id for f in findings}

    def test_private_key_block(self, tmp_path):
        findings = self._scan(
            tmp_path,
            'KEY = "-----BEGIN PRIVATE KEY-----\\nMII...\\n-----END PRIVATE KEY-----"\n',
        )
        assert "secrets-private-key" in {f.rule_id for f in findings}

    def test_no_false_positive_on_clean_code(self, tmp_path):
        findings = self._scan(
            tmp_path,
            'name = "alice"\nresult = compute(name)\n',
        )
        assert findings == []
