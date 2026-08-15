"""Abstract scanner base class and scanner registry."""

from .base import BaseScanner
from .registry import (
    register,
    get_scanner,
    list_scanners,
    all_scanners,
    create_scanners,
)

# Import the static scanner package so it self-registers at import time.
from . import static  # noqa: E402,F401

# Import the remaining scanners so they self-register via @register.
from . import dependency, fuzz, llm, secrets  # noqa: E402,F401

__all__ = [
    "BaseScanner",
    "register",
    "get_scanner",
    "list_scanners",
    "all_scanners",
    "create_scanners",
]
