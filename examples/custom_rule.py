"""How to write and register a custom static rule.

This example defines a rule that flags any use of ``print(`` in production
code (a stand-in for a real lint/safety rule), appends it to the global rule
list, and demonstrates scanning a small snippet with :class:`StaticScanner`.
"""
from __future__ import annotations

from vulnforge.scanners.static.rule import StaticRule
from vulnforge.scanners.static.rules import RULES, register_all
from vulnforge.scanners.static.scanner import StaticScanner
from vulnforge.models import Target


def make_custom_rule() -> StaticRule:
    """Build a custom StaticRule.

    A :class:`StaticRule` is a regex-based detector.  The fields mirror the
    bundled rules so you can drop your own rules into the same pipeline.
    """
    return StaticRule(
        id="custom-no-print",
        title="Avoid print() in library code",
        description=(
            "print() leaks to stdout and is often left in by mistake in "
            "library / production code. Use a logger instead."
        ),
        severity="low",
        patterns=[r"\bprint\s*\("],
        cwe="",
        recommendation="Replace print() with a configured logger.",
        extensions=[".py"],
        flags=0,
    )


def main() -> int:
    # 1. Create and register the custom rule.
    rule = make_custom_rule()
    RULES.append(rule)
    register_all()  # no-op safety hook; keeps rule registries consistent.

    # 2. Build a target pointing at a tiny sample file.
    sample = "def main():\n    print('hello world')\n"
    import tempfile
    import os

    fd, path = tempfile.mkstemp(suffix=".py", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(sample)

        targets = [Target(path=path, kind="file", language="python")]

        # 3. Scan with the static scanner.
        scanner = StaticScanner()
        findings = scanner.scan(targets, config={})

        for finding in findings:
            print(
                f"[{finding.severity.value}] {finding.rule_id} "
                f"@ {finding.file_path}:{finding.line} — {finding.title}"
            )
        print(f"Total findings: {len(findings)}")
    finally:
        os.unlink(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
