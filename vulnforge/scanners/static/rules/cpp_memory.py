"""C/C++ memory-safety detection rules (CWE-787/125/190/476)."""

from __future__ import annotations

from typing import List

from ..rule import StaticRule

RULES: List[StaticRule] = [
    StaticRule(
        id="cpp-strcpy",
        title="Unsafe strcpy",
        description="strcpy can overflow the destination buffer.",
        severity="high",
        patterns=[r"\bstrcpy\s*\("],
        cwe="CWE-787",
        recommendation="Use strncpy/stcpy_s or a bounded copy.",
        extensions=[".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"],
    ),
    StaticRule(
        id="cpp-strcat",
        title="Unsafe strcat",
        description="strcat can overflow the destination buffer.",
        severity="high",
        patterns=[r"\bstrcat\s*\("],
        cwe="CWE-787",
        recommendation="Use a bounded concatenation function.",
        extensions=[".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"],
    ),
    StaticRule(
        id="cpp-sprintf",
        title="Unsafe sprintf",
        description="sprintf writes into a fixed buffer without bounds checking.",
        severity="high",
        patterns=[r"\bsprintf\s*\("],
        cwe="CWE-787",
        recommendation="Use snprintf with an explicit size.",
        extensions=[".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"],
    ),
    StaticRule(
        id="cpp-gets",
        title="Unsafe gets",
        description="gets() reads unbounded input into a fixed buffer.",
        severity="critical",
        patterns=[r"\bgets\s*\("],
        cwe="CWE-787",
        recommendation="Use fgets with a buffer size.",
        extensions=[".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"],
    ),
    StaticRule(
        id="cpp-scanf-s",
        title="Unsafe scanf %s",
        description="scanf with %s reads without a width limit.",
        severity="high",
        patterns=[r"\bscanf\s*\(\s*[\"'][^\"']*%s"],
        cwe="CWE-787",
        recommendation="Use a width specifier (e.g. %127s).",
        extensions=[".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"],
    ),
    StaticRule(
        id="cpp-memcpy",
        title="Unsafe memory copy",
        description="memcpy/memmove/strncpy may copy without bounds checks.",
        severity="medium",
        patterns=[r"\b(memcpy|memmove|strncpy)\s*\("],
        cwe="CWE-787",
        recommendation="Verify destination size before copying.",
        extensions=[".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"],
    ),
    StaticRule(
        id="cpp-malloc-overflow",
        title="Integer overflow in allocation",
        description="malloc/calloc size is computed by multiplication (overflow risk).",
        severity="medium",
        patterns=[r"(?i)\b(malloc|calloc|realloc)\s*\(\s*[^)]*\*\s*sizeof\s*\("],
        cwe="CWE-190",
        recommendation="Check for multiplication overflow before allocating.",
        extensions=[".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"],
    ),
    StaticRule(
        id="cpp-null-deref",
        title="Possible NULL pointer dereference",
        description="A pointer is dereferenced right after assignment/return without a null check.",
        severity="medium",
        patterns=[r"(?i)(?:return|\b=\s*)\*\s*\w+\s*;"],
        cwe="CWE-476",
        recommendation="Check pointers for NULL before dereferencing.",
        extensions=[".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"],
    ),
]

__all__ = ["RULES"]
