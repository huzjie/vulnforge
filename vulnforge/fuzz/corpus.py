"""Seed corpus management with JSON persistence.

The corpus stores raw ``bytes`` seeds, deduplicated while preserving insertion
order.  It is persisted as hex strings in ``<corpus_dir>/corpus.json`` so it
survives across runs.
"""

import json
import os
import random
from typing import Any, Dict, Iterable, List, Optional, Union

_RNGType = Union[random.Random, "random.SystemRandom"]


class Corpus:
    """A deduplicated, order-preserving collection of seed inputs."""

    def __init__(self, config: Optional[Dict[str, Any]] = None, corpus_dir: Optional[str] = None) -> None:
        config = config or {}
        fuzz_cfg: Dict[str, Any] = config.get("fuzz", {}) or {}
        self.corpus_dir: str = corpus_dir or fuzz_cfg.get("corpus_dir") or os.path.join(".", ".corpus")
        self._entries: List[bytes] = []
        self._seen: set = set()
        self._load()

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    def add(self, data: bytes) -> bool:
        """Add a seed if not already present; return whether it was added."""
        if data in self._seen:
            return False
        self._seen.add(data)
        self._entries.append(data)
        return True

    def extend(self, seeds: Iterable[bytes]) -> None:
        """Add multiple seeds, ignoring duplicates."""
        for seed in seeds:
            self.add(seed)

    def pick(self, rng: Optional[_RNGType] = None) -> bytes:
        """Return a random seed (or an empty byte string if empty)."""
        rng = rng or random
        if not self._entries:
            return b""
        return rng.choice(self._entries)

    def save(self) -> str:
        """Persist the corpus to disk; return the file path written."""
        os.makedirs(self.corpus_dir, exist_ok=True)
        path = os.path.join(self.corpus_dir, "corpus.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump([entry.hex() for entry in self._entries], fh)
        return path

    def _load(self) -> None:
        path = os.path.join(self.corpus_dir, "corpus.json")
        if not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8") as fh:
                hex_entries = json.load(fh)
            for hx in hex_entries:
                self.add(bytes.fromhex(hx))
        except (ValueError, TypeError, OSError, json.JSONDecodeError):
            # Corrupt or unreadable corpus: start fresh rather than crashing.
            self._entries = []
            self._seen = set()
