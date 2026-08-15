"""Aggregates all bundled static rules into a single list."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

from . import (
    auth,
    code_quality,
    command_injection,
    cpp_memory,
    crypto,
    deserialization,
    go_rules,
    injection_other,
    java_rules,
    path_traversal,
    python_rules,
    secrets,
    sql_injection,
    ssrf,
    xss,
)

# Modules contributing rules, in load order.
_RULE_MODULES = [
    secrets,
    sql_injection,
    xss,
    path_traversal,
    command_injection,
    crypto,
    deserialization,
    ssrf,
    auth,
    injection_other,
    code_quality,
    cpp_memory,
    go_rules,
    java_rules,
    python_rules,
]

#: The combined list of every bundled static rule.
RULES: List[StaticRule] = []
for _module in _RULE_MODULES:
    RULES.extend(getattr(_module, "RULES", []))


def register_all() -> List[StaticRule]:
    """Return the full combined rule list (idempotent helper).

    Returns:
        The aggregated list of all bundled :class:`StaticRule` objects.
    """
    return RULES


__all__ = ["RULES", "register_all"]
