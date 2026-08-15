"""Deliberately vulnerable example: Server-Side Request Forgery (CWE-918)."""
import requests


def fetch_url(url: str) -> str:
    """Fetch an arbitrary user-supplied URL — vulnerable to SSRF."""
    # vulnforge-static: ssrf
    resp = requests.get(url, timeout=10)
    return resp.text


def fetch_metadata() -> str:
    """Fetch the cloud metadata endpoint without any allow-list."""
    return fetch_url("http://169.254.169.254/latest/meta-data/")
