"""The fuzzing loop.

:class:`FuzzEngine` drives a simple mutation-based fuzzing campaign against a
single ``target_fn(data: bytes)`` callable.  It seeds a :class:`Corpus`, mutates
inputs via :func:`vulnforge.fuzz.mutator.mutate`, and records any exception as a
:class:`Crash`.  The loop honours an iteration cap, an overall runtime budget,
and an optional per-input timeout.
"""

import random
import time
from typing import Callable, List, Optional

from vulnforge.errors import FuzzTimeoutError

from .corpus import Corpus
from .crash import Crash, CrashCollector
from .mutator import mutate
from .sanitizers import Sanitizer


class FuzzEngine:
    """A lightweight mutation fuzzing engine."""

    def __init__(self, config: Optional[dict] = None) -> None:
        self.config: dict = config or {}
        fuzz_cfg: dict = self.config.get("fuzz", {}) or {}

        self.default_iterations: int = int(fuzz_cfg.get("max_iterations", 1000))
        self.default_max_runtime: Optional[float] = self._opt_float(
            fuzz_cfg.get("max_runtime_seconds")
        )
        self.input_timeout: Optional[float] = self._opt_float(fuzz_cfg.get("input_timeout"))
        self.seed_value: int = int(fuzz_cfg.get("seed", 0))

        self.sanitizer = Sanitizer()
        self.collector = CrashCollector(crash_dir=fuzz_cfg.get("crash_dir"))
        self.corpus = Corpus(config)

        #: Optional ``progress(iteration, total)`` callback.
        self.on_progress: Optional[Callable[[int, int], None]] = None

        #: Set by :meth:`fuzz` to allow external interruption.
        self.interrupted: bool = False

    @staticmethod
    def _opt_float(value) -> Optional[float]:
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def fuzz(
        self,
        target_fn: Callable[[bytes], None],
        seeds: List[bytes],
        iterations: Optional[int] = None,
        max_runtime: Optional[float] = None,
    ) -> List[Crash]:
        """Run a fuzzing campaign against ``target_fn``.

        Parameters
        ----------
        target_fn:
            Callable accepting ``bytes``; raise to signal a crash.
        seeds:
            Initial corpus seeds.
        iterations:
            Number of fuzz iterations (defaults to config ``max_iterations``).
        max_runtime:
            Overall runtime budget in seconds (defaults to config).

        Returns
        -------
        List[Crash]:
            All crashes collected during the run.

        Raises
        ------
        FuzzTimeoutError:
            When the overall runtime budget is exhausted.
        """
        iterations = int(iterations if iterations is not None else self.default_iterations)
        max_runtime = max_runtime if max_runtime is not None else self.default_max_runtime

        rng = random.Random(self.seed_value)
        for seed in seeds:
            self.corpus.add(seed)

        start = time.monotonic()
        self.interrupted = False

        for i in range(iterations):
            if self.interrupted:
                break

            if max_runtime is not None and (time.monotonic() - start) > max_runtime:
                raise FuzzTimeoutError(
                    f"fuzzing exceeded max_runtime={max_runtime}s after {i} iterations"
                )

            seed = self.corpus.pick(rng)
            data = mutate(seed, rng)
            self.corpus.add(data)

            try:
                self._run_target(target_fn, data)
            except Exception as exc:  # noqa: BLE001 - record every crash
                self.collector.record(data, (type(exc), exc, exc.__traceback__), i)

            if self.on_progress is not None:
                self.on_progress(i + 1, iterations)

        return self.collector.list()

    def _run_target(self, target_fn: Callable[[bytes], None], data: bytes) -> None:
        """Invoke ``target_fn``, applying a per-input timeout if configured."""
        timeout = self.input_timeout
        if not timeout:
            target_fn(data)
            return

        from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FuturesTimeout

        executor = ThreadPoolExecutor(max_workers=1)
        future: Future = executor.submit(target_fn, data)
        try:
            future.result(timeout=timeout)
        except FuturesTimeout as exc:
            raise FuzzTimeoutError(f"target exceeded input timeout {timeout}s") from exc
        finally:
            executor.shutdown(wait=False)
