"""Abstract base class for all vulnforge scanners."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Generator, List, Tuple

from ..models import Finding, Target

# Directories skipped while iterating files within a target directory.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", "dist", "build", ".tox", ".idea", ".vscode",
}


class BaseScanner(ABC):
    """Base class for scanners.

    Subclasses must set the ``name`` class attribute and implement
    :meth:`scan`.
    """

    name: str = "base"

    @abstractmethod
    def scan(self, targets: List[Target], config: dict) -> List[Finding]:
        """Scan targets and return a list of findings.

        Args:
            targets: Targets to scan.
            config: Merged configuration dict.

        Returns:
            A list of :class:`Finding` objects.
        """
        raise NotImplementedError

    def _iter_files(self, targets: List[Target]) -> Generator[Tuple[Target, str], None, None]:
        """Yield ``(target, file_path)`` for every file across the targets.

        File targets are yielded directly; directory/repo targets are walked
        recursively, skipping vendor/generated directories.

        Args:
            targets: Targets to iterate.

        Yields:
            Tuples of ``(Target, file_path)``.
        """
        for target in targets:
            if target.kind == "file":
                yield target, target.path
            elif target.kind in ("directory", "repo"):
                for root, dirs, files in os.walk(target.path):
                    dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
                    for filename in files:
                        yield target, os.path.join(root, filename)


__all__ = ["BaseScanner"]
