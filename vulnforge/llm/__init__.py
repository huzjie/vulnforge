"""LLM provider registry and factory.

The registry maps a provider *type* (``mock``, ``openai_compat``, ``anthropic``,
``gemini``, ``ollama``) to its class.  :func:`get_provider` instantiates a
provider from a flat configuration dictionary.
"""

from typing import Any, Dict, List

from .anthropic import AnthropicProvider
from .base import BaseProvider
from .gemini import GeminiProvider
from .mock import MockProvider
from .ollama import OllamaProvider
from .openai_compat import OpenAICompatProvider

#: Provider type -> provider class registry.
PROVIDERS: Dict[str, type] = {
    MockProvider.name: MockProvider,
    OpenAICompatProvider.name: OpenAICompatProvider,
    AnthropicProvider.name: AnthropicProvider,
    GeminiProvider.name: GeminiProvider,
    OllamaProvider.name: OllamaProvider,
}

__all__ = [
    "PROVIDERS",
    "BaseProvider",
    "get_provider",
    "list_providers",
    "MockProvider",
    "OpenAICompatProvider",
    "AnthropicProvider",
    "GeminiProvider",
    "OllamaProvider",
]


def get_provider(name: str, cfg: Dict[str, Any] = None) -> BaseProvider:
    """Instantiate a provider by its type name.

    Parameters
    ----------
    name:
        Provider type, e.g. ``"openai_compat"``.
    cfg:
        Flat provider configuration (base_url / model / api_key / ...).

    Raises
    ------
    ValueError:
        If ``name`` is not a known provider type.
    """
    cfg = cfg or {}
    cls = PROVIDERS.get(name)
    if cls is None:
        raise ValueError(
            f"unknown LLM provider: {name!r}; available: {', '.join(list_providers())}"
        )
    return cls(cfg)


def list_providers() -> List[str]:
    """Return the sorted list of registered provider type names."""
    return sorted(PROVIDERS.keys())
