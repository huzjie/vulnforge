"""Scanner registry.

Scanners register themselves via the :func:`register` decorator.  The engine
uses :func:`create_scanners` to instantiate the enabled subset.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from .base import BaseScanner

_REGISTRY: Dict[str, Type[BaseScanner]] = {}


def register(cls: Type[BaseScanner]) -> Type[BaseScanner]:
    """Register a scanner class by its ``name`` attribute.

    Can be used as a decorator::

        @register
        class MyScanner(BaseScanner):
            name = "my"

    Args:
        cls: The scanner class to register.

    Returns:
        The class itself (so it can be used as a decorator).
    """
    name = getattr(cls, "name", None)
    if not name:
        raise ValueError("scanner class must define a non-empty 'name'")
    _REGISTRY[name] = cls
    return cls


def get_scanner(name: str) -> Optional[Type[BaseScanner]]:
    """Return a registered scanner class by name, or ``None``."""
    return _REGISTRY.get(name)


def list_scanners() -> List[str]:
    """Return the sorted list of registered scanner names."""
    return sorted(_REGISTRY.keys())


def all_scanners() -> List[BaseScanner]:
    """Instantiate and return every registered scanner."""
    return [cls() for cls in _REGISTRY.values()]


def create_scanners(enabled: dict) -> List[BaseScanner]:
    """Instantiate the enabled, registered scanners.

    Args:
        enabled: Mapping of scanner name to a truthy/falsy switch (typically
            the ``scanners`` section of the config).

    Returns:
        A list of scanner instances for names that are both registered and
        enabled.
    """
    scanners: List[BaseScanner] = []
    for name, cls in _REGISTRY.items():
        if enabled.get(name, False):
            scanners.append(cls())
    return scanners


__all__ = [
    "register",
    "get_scanner",
    "list_scanners",
    "all_scanners",
    "create_scanners",
    "_REGISTRY",
]
