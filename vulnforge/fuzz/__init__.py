"""Coverage-guided fuzzing primitives for vulnforge.

This package is a small, standard-library-only fuzzing toolkit: a persistent
seed :class:`Corpus`, a :func:`mutator <vulnforge.fuzz.mutator.mutate>` that
produces byte-level variations, a :class:`CrashCollector` for saving crashing
inputs, a :class:`Sanitizer` for classifying failures, and the top-level
:class:`FuzzEngine` that drives the loop.
"""

from .corpus import Corpus
from .crash import Crash, CrashCollector
from .engine import FuzzEngine
from .mutator import mutate
from .sanitizers import Sanitizer

__all__ = [
    "Corpus",
    "Crash",
    "CrashCollector",
    "FuzzEngine",
    "Sanitizer",
    "mutate",
]
