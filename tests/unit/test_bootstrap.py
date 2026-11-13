"""Tests for the dependency-free bootstrap layer."""

from pathlib import Path

from netsentinel import __version__
from netsentinel.app import build_parser
from netsentinel.infrastructure.config import AppConfig


def test_version_is_defined() -> None:
    assert __version__ == "0.1.0"


def test_parser_accepts_configuration_check() -> None:
    args = build_parser().parse_args(["--check-config"])
    assert args.check_config is True


def test_configuration_uses_environment_overrides(
    monkeypatch, tmp_path: Path
) -> None:
    data_path = tmp_path / "runtime"
    report_path = tmp_path / "reports"
    database_path = tmp_path / "state" / "netsentinel.sqlite3"
    monkeypatch.setenv("NETSENTINEL_DATA_DIR", str(data_path))
    monkeypatch.setenv("NETSENTINEL_REPORT_DIR", str(report_path))
    monkeypatch.setenv("NETSENTINEL_DATABASE_PATH", str(database_path))
    monkeypatch.setenv("NETSENTINEL_NMAP_PATH", "C:/Program Files/Nmap/nmap.exe")
    monkeypatch.setenv("NETSENTINEL_LOG_LEVEL", "debug")
    monkeypatch.setenv("NETSENTINEL_MAX_SCOPE_HOSTS", "128")
    monkeypatch.setenv("NETSENTINEL_MAX_PORTS", "512")
    monkeypatch.setenv("NETSENTINEL_MAX_CONCURRENCY", "8")
    monkeypatch.setenv("NETSENTINEL_MAX_RATE_PER_SECOND", "12.5")
    monkeypatch.setenv("NETSENTINEL_CONNECT_TIMEOUT_SECONDS", "0.75")

    config = AppConfig.from_environment()

    assert config.data_directory == data_path
    assert config.report_directory == report_path
    assert config.database_path == database_path
    assert config.nmap_path == "C:/Program Files/Nmap/nmap.exe"
    assert config.log_level == "DEBUG"
    assert config.max_scope_hosts == 128
    assert config.max_ports == 512
    assert config.max_concurrency == 8
    assert config.max_rate_per_second == 12.5
    assert config.connect_timeout_seconds == 0.75


def test_configuration_rejects_unknown_log_level(monkeypatch) -> None:
    monkeypatch.setenv("NETSENTINEL_LOG_LEVEL", "verbose")

    try:
        AppConfig.from_environment()
    except ValueError as exc:
        assert "standard log level" in str(exc)
    else:
        raise AssertionError("invalid log level should be rejected")
