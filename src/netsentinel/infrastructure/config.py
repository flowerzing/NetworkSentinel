"""Validated configuration for the NetSentinel bootstrap."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Small, dependency-free configuration object for the first stage."""

    data_directory: Path
    report_directory: Path
    nmap_path: str | None
    log_level: str
    max_scope_hosts: int = 256
    max_concurrency: int = 16
    connect_timeout_seconds: float = 1.5

    @classmethod
    def from_environment(cls) -> AppConfig:
        """Create configuration from safe defaults and environment overrides."""
        data_directory = Path(
            os.environ.get(
                "NETSENTINEL_DATA_DIR",
                Path.home() / "AppData" / "Local" / "NetSentinel",
            )
        ).expanduser()
        report_directory = Path(
            os.environ.get("NETSENTINEL_REPORT_DIR", data_directory / "reports")
        ).expanduser()
        nmap_path = os.environ.get("NETSENTINEL_NMAP_PATH") or None
        log_level = os.environ.get("NETSENTINEL_LOG_LEVEL", "INFO").upper()
        if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("NETSENTINEL_LOG_LEVEL must be a standard log level")
        return cls(
            data_directory=data_directory,
            report_directory=report_directory,
            nmap_path=nmap_path,
            log_level=log_level,
        )

    def describe(self) -> str:
        """Return a human-readable summary without exposing secrets."""
        nmap = self.nmap_path or "not configured (optional)"
        return "\n".join(
            (
                "NetSentinel configuration is valid.",
                f"data_directory={self.data_directory}",
                f"report_directory={self.report_directory}",
                f"nmap_path={nmap}",
                f"log_level={self.log_level}",
                f"max_scope_hosts={self.max_scope_hosts}",
                f"max_concurrency={self.max_concurrency}",
                f"connect_timeout_seconds={self.connect_timeout_seconds}",
            )
        )
