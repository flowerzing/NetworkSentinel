"""Tests for the constrained optional Nmap service adapter."""

from ipaddress import IPv4Address
from pathlib import Path
from uuid import uuid4

import pytest

from netsentinel.application.control import CancellationToken, RateLimiter
from netsentinel.domain.errors import OperationCancelled, ToolExecutionError
from netsentinel.infrastructure.scanning.nmap_services import (
    NmapServicesAdapter,
    build_nmap_command,
    diagnose_nmap,
    parse_nmap_xml,
)

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.50.1" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.6" extrainfo="protocol 2.0" />
      </port>
      <port protocol="udp" portid="53">
        <state state="open" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


class FakeProcess:
    def __init__(self, *, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.terminated = False

    def poll(self):
        return self.returncode

    def communicate(self, timeout=None):
        return self.stdout, self.stderr

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.terminated = True


def test_build_nmap_command_uses_fixed_safe_arguments() -> None:
    command = build_nmap_command(
        "C:/Program Files/Nmap/nmap.exe",
        (IPv4Address("192.168.50.1"), IPv4Address("192.168.50.2")),
        (22, 80),
        host_timeout_seconds=1.5,
    )

    assert command == (
        "C:/Program Files/Nmap/nmap.exe",
        "-sV",
        "-Pn",
        "-n",
        "--open",
        "--max-retries",
        "1",
        "--host-timeout",
        "1.5s",
        "-p",
        "22,80",
        "-oX",
        "-",
        "192.168.50.1",
        "192.168.50.2",
    )
    assert "--script" not in command


def test_parse_nmap_xml_returns_only_supported_tcp_evidence() -> None:
    observations = parse_nmap_xml(NMAP_XML)

    assert len(observations) == 1
    assert observations[0].address == IPv4Address("192.168.50.1")
    assert observations[0].port == 22
    assert observations[0].state == "open"
    assert observations[0].service == "ssh"
    assert observations[0].version == "OpenSSH 9.6 protocol 2.0"
    assert observations[0].source.value == "nmap"


def test_nmap_adapter_invokes_process_without_shell(tmp_path: Path) -> None:
    executable = tmp_path / "nmap.exe"
    executable.write_bytes(b"test placeholder")
    process = FakeProcess(stdout=NMAP_XML)
    calls = []

    def popen(command, **kwargs):
        calls.append((command, kwargs))
        return process

    observations = NmapServicesAdapter(
        nmap_path=str(executable),
        popen=popen,
    ).scan(
        (IPv4Address("192.168.50.1"),),
        (22,),
        timeout_seconds=1.0,
        max_concurrency=4,
        rate_limiter=RateLimiter(25),
        cancellation=CancellationToken(),
        job_id=uuid4(),
    )

    assert len(observations) == 1
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["text"] is True
    assert "--script" not in calls[0][0]


def test_nmap_adapter_checks_cancellation_before_starting_process(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "nmap.exe"
    executable.write_bytes(b"test placeholder")
    token = CancellationToken()
    token.cancel()

    def unexpected_popen(command, **kwargs):
        raise AssertionError("Nmap must not start after cancellation")

    with pytest.raises(OperationCancelled):
        NmapServicesAdapter(
            nmap_path=str(executable),
            popen=unexpected_popen,
        ).scan(
            (IPv4Address("192.168.50.1"),),
            (22,),
            timeout_seconds=1.0,
            max_concurrency=4,
            rate_limiter=RateLimiter(25),
            cancellation=token,
            job_id=uuid4(),
        )


def test_nmap_adapter_reports_nonzero_exit(tmp_path: Path) -> None:
    executable = tmp_path / "nmap.exe"
    executable.write_bytes(b"test placeholder")

    with pytest.raises(ToolExecutionError, match="status 2"):
        NmapServicesAdapter(
            nmap_path=str(executable),
            popen=lambda command, **kwargs: FakeProcess(
                returncode=2,
                stderr="permission denied",
            ),
        ).scan(
            (IPv4Address("192.168.50.1"),),
            (22,),
            timeout_seconds=1.0,
            max_concurrency=4,
            rate_limiter=RateLimiter(25),
            cancellation=CancellationToken(),
            job_id=uuid4(),
        )


def test_nmap_diagnostic_reports_missing_explicit_path(tmp_path: Path) -> None:
    diagnostic = diagnose_nmap(str(tmp_path / "missing-nmap.exe"))

    assert diagnostic.available is False
    assert diagnostic.executable is None
    assert "not found" in diagnostic.message
