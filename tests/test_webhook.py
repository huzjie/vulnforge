"""Tests for GitHub webhook utilities in :mod:`vulnforge.webhook`."""
from __future__ import annotations

import hashlib
import hmac

from vulnforge.webhook import parse_github_event, verify_signature


def _sign(payload: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return "sha256=" + digest


class TestVerifySignature:
    def test_valid_signature(self):
        payload = b'{"action": "opened"}'
        secret = "topsecret"
        assert verify_signature(payload, _sign(payload, secret), secret) is True

    def test_wrong_secret(self):
        payload = b'{"action": "opened"}'
        assert verify_signature(payload, _sign(payload, "right"), "wrong") is False

    def test_tampered_payload(self):
        secret = "s3cret"
        sig = _sign(b"original", secret)
        assert verify_signature(b"tampered", sig, secret) is False

    def test_empty_secret_returns_false(self):
        payload = b"data"
        assert verify_signature(payload, _sign(payload, "x"), "") is False

    def test_empty_signature_returns_false(self):
        assert verify_signature(b"data", "", "secret") is False


class TestParseGithubEvent:
    def test_pull_request_event(self):
        payload = {
            "action": "opened",
            "number": 7,
            "repository": {"full_name": "acme/app"},
            "pull_request": {
                "head": {"ref": "feature/x", "sha": "abc123"},
                "base": {"ref": "main"},
                "title": "Add feature",
            },
        }
        event = parse_github_event("pull_request", payload)
        assert event["event"] == "pull_request"
        assert event["repo"] == "acme/app"
        assert event["branch"] == "feature/x"
        assert event["commit"] == "abc123"

    def test_push_event(self):
        payload = {
            "ref": "refs/heads/main",
            "after": "deadbeef",
            "repository": {"full_name": "acme/app"},
            "commits": [{"id": "deadbeef"}],
        }
        event = parse_github_event("push", payload)
        assert event["event"] == "push"
        assert event["branch"] == "main"
        assert event["commit"] == "deadbeef"

    def test_unknown_event_returns_none(self):
        assert parse_github_event("issues", {}) is None

    def test_empty_event_returns_none(self):
        assert parse_github_event("", {"repository": {"full_name": "x"}}) is None
