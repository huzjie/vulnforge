"""Crash classification.

:class:`Sanitizer` maps an exception (or an ``exc_info`` tuple) to a coarse
crash category — ``timeout``, ``exception``, ``out-of-bounds``, ``assertion`` —
which is then attached to :class:`vulnforge.fuzz.crash.Crash` records and used
by the scanners to assign rule IDs / severities.
"""

from typing import Union

ExcInfo = tuple


class Sanitizer:
    """Classify a raised exception into a crash category."""

    def classify(self, exc) -> str:
        """Return a crash category string for an exception or exc_info tuple."""
        ex = self._unwrap(exc)
        if ex is None:
            return "unknown"

        name = type(ex).__name__
        message = str(ex).lower()

        # Timeout (either an explicit FuzzTimeoutError, the built-in
        # TimeoutError, or anything mentioning a timeout).
        if name in ("TimeoutError", "FuzzTimeoutError") or "timeout" in message:
            return "timeout"

        # Assertion failures (sanity checks in the target).
        if name == "AssertionError":
            return "assertion"

        # Out-of-bounds access (list/tuple indexing, buffer overrun signals).
        if name in ("IndexError", "KeyError") or "index out of range" in message:
            return "out-of-bounds"

        # Recursion / stack exhaustion.
        if name == "RecursionError":
            return "stack-overflow"

        # Generic crash.
        return "exception"

    @staticmethod
    def _unwrap(exc) -> Union[BaseException, None]:
        """Extract the exception object from either an exception or exc_info."""
        if isinstance(exc, tuple):
            if len(exc) >= 2 and exc[1] is not None:
                return exc[1]
            return None
        if isinstance(exc, BaseException):
            return exc
        return None
