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

    config = AppConfig.from_environment()

    assert config.data_directory == data_path
    assert config.report_directory == report_path
    assert config.database_path == database_path
    assert config.nmap_path == "C:/Program Files/Nmap/nmap.exe"
    assert config.log_level == "DEBUG"


def test_configuration_rejects_unknown_log_level(monkeypatch) -> None:
    monkeypatch.setenv("NETSENTINEL_LOG_LEVEL", "verbose")

    try:
        AppConfig.from_environment()
    except ValueError as exc:
        assert "standard log level" in str(exc)
    else:
        raise AssertionError("invalid log level should be rejected")
