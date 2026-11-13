"""Application bootstrap and command-line entry point."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from netsentinel import __version__
from netsentinel.infrastructure.config import AppConfig
from netsentinel.infrastructure.logging_setup import configure_logging


def build_parser() -> argparse.ArgumentParser:
    """Build the small bootstrap CLI used by the application entry point."""
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description="Defensive network visibility for authorized audits.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"NetSentinel {__version__}",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate and display local configuration without opening the GUI",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Start NetSentinel or run a non-GUI bootstrap check."""
    args = build_parser().parse_args(argv)
    config = AppConfig.from_environment()
    configure_logging(config.log_level)

    if args.check_config:
        print(config.describe())
        return 0

    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:
        print(
            "PySide6 is required to start the desktop application. "
            "Install the project dependencies first.",
            file=sys.stderr,
        )
        print(f"Import detail: {exc}", file=sys.stderr)
        return 1

    from netsentinel.ui.main_window import MainWindow

    application = QApplication(list(argv) if argv is not None else sys.argv)
    application.setApplicationName("NetSentinel")
    application.setApplicationVersion(__version__)
    window = MainWindow(config)
    window.show()
    return application.exec()
