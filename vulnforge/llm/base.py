"""LLM provider abstract base class.

All providers share a minimal, zero-dependency interface: given a ``prompt``
(and an optional ``system`` instruction), return the model's completion as a
plain ``str``.  Concrete providers live in sibling modules and register
themselves into :data:`vulnforge.llm.PROVIDERS`.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseProvider(ABC):
    """Abstract base for an LLM provider.

    Attributes
    ----------
    name:
        Provider type identifier, e.g. ``"mock"`` or ``"openai_compat"``.
    cfg:
        Provider configuration dictionary (flat), typically the resolved
        ``config["llm"]["providers"][<name>]`` merged with top-level LLM
        settings such as ``max_tokens`` / ``temperature``.
    """

    name: str = "base"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg: Dict[str, Any] = cfg or {}

    @abstractmethod
    def complete(self, prompt: str, system: str = "") -> str:
        """Return the model completion for ``prompt``.

        Implementations must raise :class:`vulnforge.errors.ProviderError` on
        any network or authentication failure so callers can degrade
        gracefully.
        """
        raise NotImplementedError
