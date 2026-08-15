"""Parallel execution helpers.

Provides a small wrapper around :class:`concurrent.futures.ThreadPoolExecutor`
that preserves input order in the returned results.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable, List, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def run_parallel(fn: Callable[[T], R], items: Iterable[T], workers: int) -> List[R]:
    """Run ``fn`` over ``items`` using a thread pool, preserving order.

    Args:
        fn: Callable taking a single item and returning a result.
        items: Iterable of input items.
        workers: Maximum number of worker threads (clamped to ``>= 1``).

    Returns:
        A list of results in the same order as the input items.
    """
    item_list = list(items)
    if not item_list:
        return []
    workers = max(1, int(workers))

    if workers == 1:
        return [fn(item) for item in item_list]

    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(fn, item_list))


__all__ = ["run_parallel"]
