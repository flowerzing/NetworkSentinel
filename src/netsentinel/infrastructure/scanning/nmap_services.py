"""Safe Nmap service/version detection through a constrained subprocess."""

from __future__ import annotations

import shutil
import subprocess
import time
import xml.etree.ElementTree as ElementTree
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any
from uuid import UUID

from netsentinel.application.control import CancellationToken, RateLimiter
from netsentinel.application.events import ProgressEvent
from netsentinel.application.port_scanning import ProgressCallback
from netsentinel.domain.enums import EvidenceSource
from netsentinel.domain.errors import (
    CapabilityError,
    OperationCancelled,
    ToolExecutionError,
    ValidationError,
)
from netsentinel.domain.models import PortObservation


@dataclass(frozen=True, slots=True)
class NmapCapability:
    """Diagnostic result for the optional Nmap executable."""

    available: bool
    executable: str | None
    message: str


class NmapServicesAdapter:
    """Run only Nmap service detection for concrete authorized targets."""

    def __init__(
        self,
        *,
        nmap_path: str | None = None,
        max_hosts: int = 256,
        max_ports: int = 1024,
        max_output_bytes: int = 8_000_000,
        max_process_timeout_seconds: float = 300.0,
        popen: Callable[..., Any] = subprocess.Popen,
    ) -> None:
        if max_hosts < 1:
            raise ValueError("max_hosts must be positive")
        if max_ports < 1:
            raise ValueError("max_ports must be positive")
        if max_output_bytes < 1:
            raise ValueError("max_output_bytes must be positive")
        if max_process_timeout_seconds <= 0:
            raise ValueError("max_process_timeout_seconds must be positive")
        self._nmap_path = nmap_path
        self._max_hosts = max_hosts
        self._max_ports = max_ports
        self._max_output_bytes = max_output_bytes
        self._max_process_timeout_seconds = max_process_timeout_seconds
        self._popen = popen

    @staticmethod
    def capability(nmap_path: str | None = None) -> NmapCapability:
        """Check Nmap availability without starting a process."""
        return diagnose_nmap(nmap_path)

    def scan(
        self,
        hosts: tuple[IPv4Address, ...],
        ports: tuple[int, ...],
        *,
        timeout_seconds: float,
        max_concurrency: int,
        rate_limiter: RateLimiter,
        cancellation: CancellationToken,
        job_id: UUID,
        progress: ProgressCallback | None = None,
    ) -> tuple[PortObservation, ...]:
        """Run constrained ``nmap -sV`` and return service evidence."""
        del max_concurrency, rate_limiter
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        _validate_work_set(hosts, ports, self._max_hosts, self._max_ports)
        cancellation.raise_if_cancelled()
        executable = _resolve_nmap_path(self._nmap_path)
        command = build_nmap_command(
            executable,
            hosts,
            ports,
            host_timeout_seconds=timeout_seconds,
        )
        process_timeout = min(
            self._max_process_timeout_seconds,
            max(timeout_seconds, timeout_seconds * max(1, len(hosts))),
        )
        output = self._execute(
            command,
            cancellation=cancellation,
            timeout_seconds=process_timeout,
        )
        if len(output.encode("utf-8")) > self._max_output_bytes:
            raise ToolExecutionError("Nmap XML output exceeded the configured limit")
        observations = parse_nmap_xml(output)
        if progress is not None:
            progress(
                ProgressEvent(
                    job_id=job_id,
                    completed=len(hosts) * len(ports),
                    total=len(hosts) * len(ports),
                    message="Nmap service detection completed",
                )
            )
        return observations

    def _execute(
        self,
        command: tuple[str, ...],
        *,
        cancellation: CancellationToken,
        timeout_seconds: float,
    ) -> str:
        try:
            process = self._popen(
                list(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
        except OSError as exc:
            raise CapabilityError(f"Unable to start Nmap: {exc}") from exc

        deadline = time.monotonic() + timeout_seconds
        try:
            while True:
                cancellation.raise_if_cancelled()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _terminate_process(process)
                    raise ToolExecutionError("Nmap exceeded the configured timeout")
                try:
                    stdout, stderr = process.communicate(
                        timeout=min(0.1, remaining)
                    )
                    break
                except subprocess.TimeoutExpired:
                    continue
        except OperationCancelled:
            _terminate_process(process)
            raise

        if process.returncode != 0:
            detail = str(stderr).strip()[:500]
            suffix = f": {detail}" if detail else ""
            raise ToolExecutionError(
                f"Nmap exited with status {process.returncode}{suffix}"
            )
        return str(stdout)


def diagnose_nmap(nmap_path: str | None = None) -> NmapCapability:
    """Resolve an explicitly configured or PATH-provided Nmap executable."""
    if nmap_path:
        candidate = Path(nmap_path).expanduser()
        if candidate.is_file():
            executable = str(candidate)
            return NmapCapability(
                True,
                executable,
                "Configured Nmap executable is available.",
            )
        return NmapCapability(
            False,
            None,
            f"Configured Nmap executable was not found: {candidate}",
        )

    resolved = shutil.which("nmap")
    if resolved:
        return NmapCapability(True, resolved, "Nmap was found on PATH.")
    return NmapCapability(
        False,
        None,
        "Nmap was not found on PATH and no executable path was configured.",
    )


def build_nmap_command(
    executable: str,
    hosts: tuple[IPv4Address, ...],
    ports: tuple[int, ...],
    *,
    host_timeout_seconds: float,
) -> tuple[str, ...]:
    """Build a fixed-argument Nmap command with no shell interpolation."""
    _validate_work_set(hosts, ports, max_hosts=len(hosts), max_ports=len(ports))
    if host_timeout_seconds <= 0:
        raise ValueError("host_timeout_seconds must be positive")
    port_spec = ",".join(str(port) for port in ports)
    return (
        executable,
        "-sV",
        "-Pn",
        "-n",
        "--open",
        "--max-retries",
        "1",
        "--host-timeout",
        f"{host_timeout_seconds:g}s",
        "-p",
        port_spec,
        "-oX",
        "-",
        *(str(host) for host in hosts),
    )


def parse_nmap_xml(xml_text: str) -> tuple[PortObservation, ...]:
    """Parse Nmap XML into evidence without inferring unsupported findings."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise ToolExecutionError("Nmap returned invalid XML output") from exc

    observed_at = datetime.now(UTC)
    observations: list[PortObservation] = []
    for host in root.findall("host"):
        address_element = host.find("address[@addrtype='ipv4']")
        if address_element is None or not address_element.get("addr"):
            continue
        try:
            address = IPv4Address(address_element.get("addr", ""))
        except ValueError:
            continue
        for port_element in host.findall("./ports/port"):
            port_text = port_element.get("portid")
            protocol = port_element.get("protocol", "").lower()
            state_element = port_element.find("state")
            state = state_element.get("state") if state_element is not None else None
            if not port_text or protocol != "tcp" or state not in {
                "open",
                "closed",
                "filtered",
            }:
                continue
            try:
                port = int(port_text)
            except ValueError:
                continue
            service_element = port_element.find("service")
            service = None
            version = None
            if service_element is not None:
                service = _text_value(service_element.get("name"))
                version = _version_text(service_element)
            observations.append(
                PortObservation(
                    address=address,
                    port=port,
                    protocol="tcp",
                    state=state,
                    service=service,
                    version=version,
                    source=EvidenceSource.NMAP,
                    observed_at=observed_at,
                )
            )
    return tuple(observations)


def _version_text(service_element: ElementTree.Element) -> str | None:
    parts = [
        _text_value(service_element.get("product")),
        _text_value(service_element.get("version")),
        _text_value(service_element.get("extrainfo")),
    ]
    values = [part for part in parts if part]
    return " ".join(values) if values else None


def _text_value(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _validate_work_set(
    hosts: tuple[IPv4Address, ...],
    ports: tuple[int, ...],
    max_hosts: int,
    max_ports: int,
) -> None:
    if not hosts:
        raise ValidationError("At least one Nmap host is required")
    if len(hosts) > max_hosts:
        raise ValidationError(f"Nmap host count exceeds the limit of {max_hosts}")
    if not ports:
        raise ValidationError("At least one Nmap port is required")
    if len(ports) > max_ports:
        raise ValidationError(f"Nmap port count exceeds the limit of {max_ports}")
    if any(not 1 <= port <= 65535 for port in ports):
        raise ValidationError("Nmap ports must be between 1 and 65535")


def _resolve_nmap_path(nmap_path: str | None) -> str:
    capability = diagnose_nmap(nmap_path)
    if capability.executable is None:
        raise CapabilityError(capability.message)
    return capability.executable


def _terminate_process(process: Any) -> None:
    """Stop a still-running Nmap process without invoking a shell."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    try:
        process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
        process.communicate(timeout=2)
