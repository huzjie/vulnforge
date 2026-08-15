"""Deliberately vulnerable example: path traversal (CWE-22)."""
import os


def read_file(filename: str) -> str:
    """Read a file using a user-controlled path — vulnerable to traversal."""
    # vulnforge-static: path-traversal
    with open(os.path.join("uploads", filename), "r", encoding="utf-8") as fh:
        return fh.read()


def delete_backup(name: str) -> None:
    """Delete a file from a user-supplied relative path."""
    # vulnforge-static: path-traversal
    os.remove(os.path.join("backups", name))
