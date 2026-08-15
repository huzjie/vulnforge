"""Configuration loading with a minimal built-in YAML parser.

vulnforge must run fully offline in ``mock`` mode without any third-party
dependencies, so configuration merging and a small YAML subset parser are
implemented here using only the standard library.

Merge priority (highest wins, applied last):

1. Built-in ``DEFAULT_CONFIG`` (offline / mock defaults).
2. Package ``config.example.yaml`` (if present).
3. ``./config.yaml`` in the current working directory (if present).
4. An explicit ``path`` passed to :func:`load_config`.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Built-in defaults: these values keep vulnforge runnable with zero config.
# ---------------------------------------------------------------------------
DEFAULT_CONFIG: Dict[str, Any] = {
    "general": {
        "mode": "mock",
        "concurrency": 8,
        "timeout_seconds": 120,
        "output_dir": "./results",
        "default_formats": ["json", "markdown", "html", "sarif"],
        "fail_on": "critical",
    },
    "targets": {
        "default_extensions": [
            ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java",
            ".c", ".cpp", ".h", ".rb", ".php", ".sh", ".bash",
            ".yml", ".yaml", ".json", ".tf", ".toml",
        ],
    },
    "scanners": {
        "static": True,
        "llm": True,
        "fuzz": True,
        "dependency": True,
        "secrets": True,
    },
    "static": {
        "min_severity": "low",
        "max_line_length": 160,
        "max_function_complexity": 20,
        "banned_imports": ["pickle", "subprocess", "eval", "exec", "yaml.load"],
    },
    "llm": {
        "default_provider": "mock",
        "max_tokens": 2048,
        "temperature": 0.0,
        "chunk_lines": 400,
        "providers": {
            "mock": {"type": "mock"},
        },
    },
    "fuzz": {
        "max_iterations": 5000,
        "max_runtime_seconds": 30,
        "corpus_dir": "./.corpus",
        "crash_dir": "./.crash",
    },
    "dependency": {
        "ecosystem": "auto",
        "osv_endpoint": "https://api.osv.dev/v1/query",
        "offline": True,
    },
    "webhook": {"enabled": False, "secret": "", "port": 8000},
    "api": {
        "host": "127.0.0.1",
        "port": 8000,
        "auth_token": "",
        "cors_origins": ["*"],
    },
}


# ---------------------------------------------------------------------------
# Minimal YAML subset parser.
# ---------------------------------------------------------------------------
_QUOTED_TOKEN_RE = re.compile(r'"[^"]*"|\'[^\']*\'|\S+')
_NUMBER_RE = re.compile(r"^-?\d+(\.\d+)?$")


def _strip_inline_comment(line: str) -> str:
    """Remove a ``#`` comment, ignoring ``#`` inside single/double quotes."""
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i]
    return line


def _parse_scalar(text: str) -> Any:
    """Parse a scalar value: quoted string, bool, null, number, or bare word."""
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
        return text[1:-1]
    low = text.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "none", "~"):
        return None
    if _NUMBER_RE.match(text):
        if "." in text:
            return float(text)
        return int(text)
    return text


def _split_top_level(text: str, sep: str = ",") -> List[str]:
    """Split on ``sep`` while respecting quotes."""
    parts: List[str] = []
    buf: List[str] = []
    in_single = False
    in_double = False
    for ch in text:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == sep and not in_single and not in_double:
            parts.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf).strip())
    return [p for p in parts if p != ""]


def _parse_list_item(text: str) -> List[Any]:
    """Parse a single ``- ...`` list item into zero or more values.

    Handles inline arrays ``[a, b]`` and the space-separated quoted-string
    form ``- ".py" ".js" ".ts"`` used by the example config.
    """
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(t) for t in _split_top_level(inner)]
    tokens = _QUOTED_TOKEN_RE.findall(text)
    if len(tokens) > 1:
        return [_parse_scalar(t) for t in tokens]
    return [_parse_scalar(text)]


def _parse_yaml(text: str) -> Dict[str, Any]:
    """Parse a minimal YAML document (dicts, lists, scalars, comments)."""
    entries: List[Tuple[int, str]] = []
    for raw in text.splitlines():
        stripped = _strip_inline_comment(raw).rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        entries.append((indent, stripped.strip()))

    value, _ = _parse_block(entries, 0, 0)
    return value if isinstance(value, dict) else {}


def _parse_block(
    entries: List[Tuple[int, str]], idx: int, indent: int
) -> Tuple[Any, int]:
    """Parse a block starting at ``idx``, returning ``(value, next_idx)``."""
    if idx >= len(entries):
        return {}, idx
    first_indent, first_content = entries[idx]
    if first_indent != indent:
        return {}, idx
    if first_content.startswith("- "):
        return _parse_list(entries, idx, indent)
    return _parse_dict(entries, idx, indent)


def _parse_dict(
    entries: List[Tuple[int, str]], idx: int, indent: int
) -> Tuple[Dict[str, Any], int]:
    """Parse a mapping block."""
    result: Dict[str, Any] = {}
    while idx < len(entries):
        e_indent, content = entries[idx]
        if e_indent < indent:
            break
        if e_indent > indent or content.startswith("- "):
            break
        key, _, value_str = content.partition(":")
        key = key.strip().strip('"').strip("'")
        value_str = value_str.strip()
        idx += 1
        if value_str == "":
            # Nested block follows on a deeper indentation level.
            if idx < len(entries) and entries[idx][0] > indent:
                child, idx = _parse_block(entries, idx, entries[idx][0])
                result[key] = child
            else:
                result[key] = None
        elif value_str.startswith("[") and value_str.endswith("]"):
            # Inline array value, e.g. ``default_formats: ["json", "markdown"]``.
            result[key] = _parse_list_item(value_str)
        else:
            result[key] = _parse_scalar(value_str)
    return result, idx


def _parse_list(
    entries: List[Tuple[int, str]], idx: int, indent: int
) -> Tuple[List[Any], int]:
    """Parse a sequence block."""
    result: List[Any] = []
    while idx < len(entries):
        e_indent, content = entries[idx]
        if e_indent < indent:
            break
        if e_indent > indent:
            idx += 1
            continue
        if content.startswith("- "):
            item_text = content[2:].strip()
            idx += 1
            if item_text == "":
                if idx < len(entries) and entries[idx][0] > indent:
                    child, idx = _parse_block(entries, idx, entries[idx][0])
                    result.append(child)
                else:
                    result.append(None)
            else:
                result.extend(_parse_list_item(item_text))
        else:
            break
    return result, idx


# ---------------------------------------------------------------------------
# Deep merge + public load entrypoint.
# ---------------------------------------------------------------------------
def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``override`` into a copy of ``base``."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _example_candidates() -> List[Path]:
    """Return candidate locations for the packaged example config."""
    pkg_dir = Path(__file__).resolve().parent
    return [
        pkg_dir / "config.example.yaml",
        pkg_dir.parent / "config.example.yaml",
    ]


def _load_yaml_file(path: Path) -> Dict[str, Any]:
    """Read and parse a YAML file, raising :class:`ConfigError` on failure."""
    from .errors import ConfigError

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    try:
        return _parse_yaml(text)
    except Exception as exc:  # pragma: no cover - defensive
        raise ConfigError(f"cannot parse config file {path}: {exc}") from exc


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load and merge configuration from all sources.

    Args:
        path: Optional explicit config file path (highest priority).

    Returns:
        A fully merged configuration dict.
    """
    config = copy.deepcopy(DEFAULT_CONFIG)

    # 1. Packaged example (if present).
    for candidate in _example_candidates():
        if candidate.is_file():
            config = deep_merge(config, _load_yaml_file(candidate))

    # 2. Local ./config.yaml.
    local = Path("config.yaml")
    if local.is_file():
        config = deep_merge(config, _load_yaml_file(local))

    # 3. Explicit path.
    if path:
        config = deep_merge(config, _load_yaml_file(Path(path)))

    return config


__all__ = ["DEFAULT_CONFIG", "load_config", "deep_merge", "_parse_yaml"]
