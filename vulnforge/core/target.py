"""Target discovery and normalization.

``TargetCollector`` expands input paths (files or directories) into a
de-duplicated list of :class:`~vulnforge.models.Target` objects, skipping
vendor/generated directories, binary files, and oversized files.
"""

from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional, Set

from ..models import Target

# Directories always skipped during traversal.
_SKIP_DIRS: Set[str] = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
    "dist", "build", ".eggs", "*.egg-info",
}

# File extension -> language mapping.
_LANG_MAP: Dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".sh": "shell",
    ".bash": "shell",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".tf": "terraform",
    ".toml": "toml",
}

# Default extensions when the config does not specify any.
_DEFAULT_EXTENSIONS: List[str] = [
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".c",
    ".cpp", ".h", ".rb", ".php", ".sh", ".bash", ".yml", ".yaml",
    ".json", ".tf", ".toml",
]

_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


def _detect_language(path: str) -> str:
    """Detect a target's language from its file name/extension."""
    base = os.path.basename(path)
    if base == "Dockerfile" or base.endswith("Dockerfile"):
        return "dockerfile"
    ext = os.path.splitext(path)[1].lower()
    return _LANG_MAP.get(ext, "")


def _is_binary(path: str) -> bool:
    """Heuristically detect binary content via a NUL byte in the first chunk."""
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(1024)
    except OSError:
        return True
    return b"\x00" in chunk


class TargetCollector:
    """Collects scan targets from a list of file/directory paths."""

    def collect(self, paths: List[str], config: dict) -> List[Target]:
        """Expand ``paths`` into a de-duplicated list of file Targets.

        Args:
            paths: Input file and/or directory paths.
            config: Configuration dict; uses ``targets.default_extensions``.

        Returns:
            A list of :class:`Target` objects with ``kind="file"``.
        """
        extensions = self._extensions(config)
        collected: List[Target] = []
        seen: Set[str] = set()

        for raw_path in paths or []:
            path = os.path.abspath(raw_path)
            if os.path.isfile(path):
                target = self._file_target(path, extensions)
                if target is not None:
                    collected.append(target)
            elif os.path.isdir(path):
                for target in self._walk_directory(path, extensions):
                    collected.append(target)

        # De-duplicate by normalized absolute path.
        unique: List[Target] = []
        for target in collected:
            key = os.path.normcase(os.path.abspath(target.path))
            if key in seen:
                continue
            seen.add(key)
            unique.append(target)
        return unique

    @staticmethod
    def _extensions(config: dict) -> Set[str]:
        """Resolve the set of allowed extensions from the config."""
        raw = (config.get("targets") or {}).get("default_extensions")
        if not raw:
            raw = _DEFAULT_EXTENSIONS
        exts: Set[str] = set()
        for item in raw:
            ext = str(item).strip().lower()
            if ext and not ext.startswith("."):
                ext = "." + ext
            if ext:
                exts.add(ext)
        if not exts:
            exts = set(_DEFAULT_EXTENSIONS)
        return exts

    def _walk_directory(self, directory: str, extensions: Set[str]) -> List[Target]:
        """Walk a directory tree, yielding file Targets."""
        targets: List[Target] = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [
                d for d in dirs
                if d not in _SKIP_DIRS and not d.startswith(".")
            ]
            for filename in files:
                file_path = os.path.join(root, filename)
                target = self._file_target(file_path, extensions)
                if target is not None:
                    targets.append(target)
        return targets

    @staticmethod
    def _file_target(path: str, extensions: Set[str]) -> Optional[Target]:
        """Build a Target for a single file, or ``None`` if it is excluded."""
        try:
            size = os.path.getsize(path)
        except OSError:
            return None
        if size > _MAX_FILE_SIZE:
            return None

        base = os.path.basename(path)
        is_dockerfile = base == "Dockerfile" or base.endswith("Dockerfile")
        ext = os.path.splitext(path)[1].lower()
        if not is_dockerfile and ext not in extensions:
            return None
        if _is_binary(path):
            return None

        return Target(
            path=path,
            kind="file",
            language=_detect_language(path),
            size=size,
        )


__all__ = ["TargetCollector"]
