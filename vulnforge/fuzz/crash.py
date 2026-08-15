"""Crash recording and persistence.

A :class:`Crash` is an immutable snapshot of a failing input.  The
:class:`CrashCollector` accumulates crashes during a fuzzing run and persists
them (both the input bytes and a JSON metadata sidecar) into a crash directory.
"""

import json
import os
import traceback
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

ExcInfo = Tuple[type, BaseException, Any]


@dataclass
class Crash:
    """A single fuzzing crash."""

    input_bytes: bytes
    crash_type: str
    exc_type: str = ""
    message: str = ""
    iteration: int = -1
    traceback_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation (input as hex)."""
        return {
            "input_hex": self.input_bytes.hex(),
            "input_size": len(self.input_bytes),
            "crash_type": self.crash_type,
            "exc_type": self.exc_type,
            "message": self.message,
            "iteration": self.iteration,
            "traceback": self.traceback_text,
        }

    @classmethod
    def from_dict(cls, obj: Dict[str, Any]) -> "Crash":
        """Reconstruct a Crash from :meth:`to_dict` output."""
        return cls(
            input_bytes=bytes.fromhex(obj.get("input_hex", "")),
            crash_type=obj.get("crash_type", "unknown"),
            exc_type=obj.get("exc_type", ""),
            message=obj.get("message", ""),
            iteration=obj.get("iteration", -1),
            traceback_text=obj.get("traceback", ""),
        )


class CrashCollector:
    """Collect and persist fuzzing crashes."""

    def __init__(self, crash_dir: Optional[str] = None) -> None:
        self.crash_dir: str = crash_dir or os.path.join(".", ".crash")
        self.crashes: List[Crash] = []

    def record(self, input_bytes: bytes, exc_info, iteration: int) -> Crash:
        """Record a crash from either an exception or an ``exc_info`` tuple."""
        exc: BaseException
        if isinstance(exc_info, tuple):
            exc = exc_info[1] if len(exc_info) > 1 and exc_info[1] is not None else BaseException("crash")
            tb = "".join(traceback.format_exception(*exc_info)) if len(exc_info) == 3 else ""
        else:
            exc = exc_info
            tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

        crash = Crash(
            input_bytes=input_bytes,
            crash_type=self._classify(exc),
            exc_type=type(exc).__name__,
            message=str(exc),
            iteration=iteration,
            traceback_text=tb,
        )
        self.crashes.append(crash)
        return crash

    @staticmethod
    def _classify(exc: BaseException) -> str:
        # Lightweight inline classification to avoid a hard import cycle; the
        # richer Sanitizer lives in vulnforge.fuzz.sanitizers.
        name = type(exc).__name__
        low = str(exc).lower()
        if name in ("TimeoutError", "FuzzTimeoutError") or "timeout" in low:
            return "timeout"
        if name == "AssertionError":
            return "assertion"
        if name == "IndexError":
            return "out-of-bounds"
        return "exception"

    def save(self, directory: Optional[str] = None) -> str:
        """Persist crashes (inputs + metadata) into ``directory`` (or default)."""
        directory = directory or self.crash_dir
        os.makedirs(directory, exist_ok=True)
        for i, crash in enumerate(self.crashes):
            with open(os.path.join(directory, f"crash_{i:05d}.bin"), "wb") as fh:
                fh.write(crash.input_bytes)
            with open(os.path.join(directory, f"crash_{i:05d}.json"), "w", encoding="utf-8") as fh:
                json.dump(crash.to_dict(), fh, ensure_ascii=False, indent=2)
        return directory

    def list(self) -> List[Crash]:
        """Return the recorded crashes."""
        return list(self.crashes)
