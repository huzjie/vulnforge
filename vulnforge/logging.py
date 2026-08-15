"""Logging helpers for vulnforge.

``get_logger`` returns a configured :class:`logging.Logger` that writes to
stdout and, optionally, to a file.  Repeated calls reuse the same logger and
never attach duplicate handlers.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Optional

_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str = "vulnforge", log_file: Optional[str] = None) -> logging.Logger:
    """Return a configured logger, attaching handlers only once.

    Args:
        name: Logger name (also used as the root namespace).
        log_file: Optional path to also write logs to a file.  When omitted,
            the ``VULNFORGE_LOG_FILE`` environment variable is consulted.

    Returns:
        A :class:`logging.Logger` instance ready for use.
    """
    logger = logging.getLogger(name)

    # Already configured: return immediately to avoid duplicate handlers.
    if getattr(logger, "_vf_configured", False):
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter(_FORMAT, _DATE_FORMAT)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    file_path = log_file or os.environ.get("VULNFORGE_LOG_FILE")
    if file_path:
        try:
            file_handler = logging.FileHandler(file_path, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError:
            # File logging is best-effort; never break stdout logging.
            pass

    logger._vf_configured = True  # type: ignore[attr-defined]
    return logger


__all__ = ["get_logger"]
