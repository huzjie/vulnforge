"""Deliberately vulnerable example: weak cryptographic algorithms (CWE-327/328)."""
import hashlib
import hmac


def hash_password(password: str) -> str:
    """Hash a password with MD5 — cryptographically broken (CWE-328)."""
    # vulnforge-static: weak-crypto
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def sha1_digest(data: str) -> str:
    """SHA-1 is collision-broken and should not be used for security (CWE-328)."""
    # vulnforge-static: weak-crypto
    return hashlib.sha1(data.encode("utf-8")).hexdigest()


def verify_mac(key: bytes, msg: bytes, digest: bytes) -> bool:
    """HMAC-MD5 is deprecated for new designs (CWE-327)."""
    # vulnforge-static: weak-crypto
    return hmac.compare_digest(hmac.new(key, msg, hashlib.md5).digest(), digest)
