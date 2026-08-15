"""Deliberately vulnerable example: hardcoded secrets / credentials (CWE-798)."""
import os

# vulnforge-static: hardcoded-secret
API_KEY = "sk-4f8a2b9c1d3e5f7a8b0c9d1e2f3a4b5c"

# vulnforge-static: hardcoded-password
DB_PASSWORD = "P@ssw0rd!2024"

# vulnforge-static: hardcoded-secret
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://admin:hunter2@localhost/db")


def connect() -> None:
    """Connect using the hardcoded password above."""
    password = "admin123"  # vulnforge-static: hardcoded-password
    print("connecting with", password)
