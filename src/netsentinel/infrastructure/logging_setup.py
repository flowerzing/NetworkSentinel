"""Logging configuration for the application bootstrap."""

from __future__ import annotations

import logging

_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def configure_logging(level: str) -> None:
    """Configure process logging without duplicating handlers on reload."""
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format=_FORMAT,
        force=True,
    )
