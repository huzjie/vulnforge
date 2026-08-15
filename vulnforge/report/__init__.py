"""Report rendering dispatch and file output.

:func:`render` dispatches on a format name to the appropriate renderer;
:func:`write` renders and writes the result to disk.
"""

import os
from typing import Optional

from vulnforge.errors import ReportError

from . import cyclonedx_report, html_report, json_report, markdown_report, sarif_report
from .summary import summarize

_FORMAT_ALIASES = {
    "json": "json",
    "markdown": "markdown",
    "md": "markdown",
    "html": "html",
    "htm": "html",
    "sarif": "sarif",
    "cyclonedx": "cyclonedx",
    "sbom": "cyclonedx",
}

_RENDERERS = {
    "json": json_report.render,
    "markdown": markdown_report.render,
    "html": html_report.render,
    "sarif": sarif_report.render,
    "cyclonedx": cyclonedx_report.render,
}


def render(report, fmt: str) -> str:
    """Render ``report`` in the given format and return the string.

    Parameters
    ----------
    report:
        A :class:`vulnforge.models.ScanReport`.
    fmt:
        One of ``json``, ``markdown``/``md``, ``html``, ``sarif``,
        ``cyclonedx``/``sbom``.

    Raises
    ------
    ReportError:
        If ``fmt`` is not a supported format.
    """
    canonical = _FORMAT_ALIASES.get((fmt or "json").lower())
    if canonical is None:
        raise ReportError(f"unsupported report format: {fmt!r}")
    renderer = _RENDERERS[canonical]
    return renderer(report)


def write(report, fmt: str, path: str) -> str:
    """Render ``report`` and write it to ``path``; return the written path."""
    content = render(report, fmt)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    return path


__all__ = [
    "render",
    "write",
    "summarize",
]
