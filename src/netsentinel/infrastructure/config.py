"""Validated configuration for the NetSentinel bootstrap."""

from __future__ import annotations

import os
from dataclasses import dataclass
from math import isfinite
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Small, dependency-free configuration object for the first stage."""

    data_directory: Path
    report_directory: Path
    database_path: Path
    nmap_path: str | None
    log_level: str
    max_scope_hosts: int = 256
    max_ports: int = 1024
    max_concurrency: int = 16
    max_rate_per_second: float = 25.0
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
        database_path = Path(
            os.environ.get(
                "NETSENTINEL_DATABASE_PATH", data_directory / "netsentinel.sqlite3"
            )
        ).expanduser()
        nmap_path = os.environ.get("NETSENTINEL_NMAP_PATH") or None
        log_level = os.environ.get("NETSENTINEL_LOG_LEVEL", "INFO").upper()
        if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("NETSENTINEL_LOG_LEVEL must be a standard log level")
        return cls(
            data_directory=data_directory,
            report_directory=report_directory,
            database_path=database_path,
            nmap_path=nmap_path,
            log_level=log_level,
            max_scope_hosts=_positive_int("NETSENTINEL_MAX_SCOPE_HOSTS", 256),
            max_ports=_positive_int("NETSENTINEL_MAX_PORTS", 1024),
            max_concurrency=_positive_int("NETSENTINEL_MAX_CONCURRENCY", 16),
            max_rate_per_second=_positive_float(
                "NETSENTINEL_MAX_RATE_PER_SECOND", 25.0
            ),
            connect_timeout_seconds=_positive_float(
                "NETSENTINEL_CONNECT_TIMEOUT_SECONDS", 1.5
            ),
        )

    def describe(self) -> str:
        """Return a human-readable summary without exposing secrets."""
        nmap = self.nmap_path or "not configured (optional)"
        return "\n".join(
            (
                "NetSentinel configuration is valid.",
                f"data_directory={self.data_directory}",
                f"report_directory={self.report_directory}",
                f"database_path={self.database_path}",
                f"nmap_path={nmap}",
                f"log_level={self.log_level}",
                f"max_scope_hosts={self.max_scope_hosts}",
                f"max_ports={self.max_ports}",
                f"max_concurrency={self.max_concurrency}",
                f"max_rate_per_second={self.max_rate_per_second}",
                f"connect_timeout_seconds={self.connect_timeout_seconds}",
            )
        )


def _positive_int(environment_name: str, default: int) -> int:
    """Read a positive integer setting from the process environment."""
    value = os.environ.get(environment_name)
    try:
        parsed = int(value) if value is not None else default
    except ValueError as exc:
        raise ValueError(f"{environment_name} must be a positive integer") from exc
    if parsed < 1:
        raise ValueError(f"{environment_name} must be a positive integer")
    return parsed


def _positive_float(environment_name: str, default: float) -> float:
    """Read a finite positive floating-point setting from the environment."""
    value = os.environ.get(environment_name)
    try:
        parsed = float(value) if value is not None else default
    except ValueError as exc:
        raise ValueError(f"{environment_name} must be a positive number") from exc
    if not isfinite(parsed) or parsed <= 0:
        raise ValueError(f"{environment_name} must be a positive number")
    return parsed
