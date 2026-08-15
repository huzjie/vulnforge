"""Byte-level mutation strategies for fuzzing.

:func:`mutate` applies one of several strategies to ``data``: single-bit flips,
byte replacements, random insertions, deletions, and dictionary-token splicing.
The exact strategy is chosen randomly using the supplied :class:`random.Random`
instance for reproducibility.
"""

import random
from typing import List, Optional, Union

_RNGType = Union[random.Random, "random.SystemRandom"]

# Interesting tokens commonly used to trigger parser/logic edge cases.
DICTIONARY_TOKENS: List[bytes] = [
    b"\x00",
    b"\xff",
    b"\xfe\xff",
    b"\n",
    b"\r\n",
    b"%s",
    b"%n",
    b"%x",
    b"%d",
    b"A" * 64,
    b"0" * 32,
    b"../" * 8,
    b"..\\" * 8,
    b"../../../../etc/passwd",
    b"<script>alert(1)</script>",
    b"'; DROP TABLE users;--",
    b" OR 1=1--",
    b"\x90" * 16,
    b"AAAA" * 256,
]


def _bit_flip(data: bytes, rng: _RNGType) -> bytes:
    if not data:
        return b"\x00"
    out = bytearray(data)
    idx = rng.randrange(len(out))
    bit = rng.randrange(8)
    out[idx] ^= 1 << bit
    return bytes(out)


def _byte_replace(data: bytes, rng: _RNGType) -> bytes:
    if not data:
        return bytes([rng.randrange(256)])
    out = bytearray(data)
    idx = rng.randrange(len(out))
    out[idx] = rng.randrange(256)
    return bytes(out)


def _insert(data: bytes, rng: _RNGType) -> bytes:
    out = bytearray(data)
    idx = rng.randrange(len(out) + 1)
    token = rng.choice(DICTIONARY_TOKENS)
    out[idx:idx] = token
    return bytes(out)


def _delete(data: bytes, rng: _RNGType) -> bytes:
    if not data:
        return b""
    out = bytearray(data)
    idx = rng.randrange(len(out))
    span = rng.randint(1, max(1, min(4, len(out) - idx)))
    del out[idx:idx + span]
    return bytes(out)


def _token_splice(data: bytes, rng: _RNGType) -> bytes:
    out = bytearray(data)
    if not out:
        return rng.choice(DICTIONARY_TOKENS)
    idx = rng.randrange(len(out))
    token = rng.choice(DICTIONARY_TOKENS)
    out[idx:idx] = token
    return bytes(out)


_STRATEGIES = (_bit_flip, _byte_replace, _insert, _delete, _token_splice)


def mutate(data: bytes, rng: Optional[_RNGType] = None) -> bytes:
    """Return a mutated copy of ``data`` using a randomly chosen strategy."""
    rng = rng or random
    strategy = rng.choice(_STRATEGIES)
    return strategy(data, rng)
