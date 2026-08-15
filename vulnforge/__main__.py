"""Entrypoint for ``python -m vulnforge``.

Delegates to the CLI entrypoint.  The CLI module may not exist yet while the
platform is under construction, so the import is guarded.
"""

from __future__ import annotations

import sys


def _run() -> int:
    """Import and run the CLI main function, returning its exit code."""
    try:
        from vulnforge.cli.main import main
    except Exception as exc:  # noqa: BLE001 - fallback while CLI is absent
        sys.stderr.write(
            "vulnforge: CLI module is not available yet (%s).\n" % exc
        )
        sys.stderr.write(
            "vulnforge: use the library API (vulnforge.core.engine) directly.\n"
        )
        return 1
    return int(main() or 0)


if __name__ == "__main__":
    sys.exit(_run())
