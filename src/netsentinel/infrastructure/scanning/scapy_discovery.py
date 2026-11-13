"""Scapy/Npcap adapter for authorized local IPv4 ARP discovery."""

from __future__ import annotations

import ctypes.util
import importlib
import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from types import ModuleType
from typing import Any

from netsentinel.application.control import CancellationToken
from netsentinel.domain.errors import CapabilityError
from netsentinel.domain.models import DiscoveryRecord, ScanScope


@dataclass(frozen=True, slots=True)
class ScapyCapability:
    """Diagnostic result for the Scapy packet capability."""

    scapy_available: bool
    npcap_available: bool
    message: str

    @property
    def available(self) -> bool:
        """Return whether the adapter can attempt an ARP operation."""
        return self.scapy_available and self.npcap_available


def diagnose_scapy() -> ScapyCapability:
    """Check Scapy and the Windows packet provider without opening a socket."""
    try:
        importlib.import_module("scapy.all")
    except ImportError:
        return ScapyCapability(
            scapy_available=False,
            npcap_available=False,
            message="Scapy is not installed; install the project dependencies first.",
        )

    if sys.platform != "win32":
        return ScapyCapability(
            scapy_available=True,
            npcap_available=True,
            message="Scapy is available; the host is not using the Windows Npcap path.",
        )

    if _npcap_library_present():
        return ScapyCapability(
            scapy_available=True,
            npcap_available=True,
            message="Scapy and an Npcap-compatible packet library are available.",
        )
    return ScapyCapability(
        scapy_available=True,
        npcap_available=False,
        message=(
            "Scapy is installed, but Npcap was not detected. Install Npcap with "
            "WinPcap API compatibility before using ARP discovery."
        ),
    )


class ScapyDiscoveryAdapter:
    """Perform bounded ARP discovery through Scapy's layer-2 socket."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 2.0,
        batch_size: int = 64,
        interface: str | None = None,
        max_hosts: int = 256,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        if max_hosts < 1:
            raise ValueError("max_hosts must be positive")
        self._timeout_seconds = timeout_seconds
        self._batch_size = batch_size
        self._interface = interface
        self._max_hosts = max_hosts

    @staticmethod
    def capability() -> ScapyCapability:
        """Return diagnostics without generating network traffic."""
        return diagnose_scapy()

    def discover(
        self,
        scope: ScanScope,
        *,
        interface: str | None = None,
        cancellation: CancellationToken | None = None,
    ) -> Iterable[DiscoveryRecord]:
        """Send ARP requests only to the concrete hosts in the supplied scope."""
        capability = diagnose_scapy()
        if not capability.available:
            raise CapabilityError(capability.message)
        scapy = _load_scapy()
        token = cancellation or CancellationToken()
        hosts = scope.hosts(limit=self._max_hosts)
        selected_interface = interface or self._interface
        results: list[DiscoveryRecord] = []

        for offset in range(0, len(hosts), self._batch_size):
            token.raise_if_cancelled()
            batch = hosts[offset : offset + self._batch_size]
            packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(
                pdst=[str(address) for address in batch]
            )
            answered, _ = scapy.srp(
                packet,
                timeout=self._timeout_seconds,
                verbose=False,
                iface=selected_interface,
            )
            results.extend(_records_from_answers(answered))
        return results


def _load_scapy() -> ModuleType:
    return importlib.import_module("scapy.all")


def _records_from_answers(answered: Iterable[Any]) -> list[DiscoveryRecord]:
    records: list[DiscoveryRecord] = []
    for sent, received in answered:
        address = IPv4Address(str(received.psrc))
        sent_time = getattr(sent, "sent_time", None)
        received_time = getattr(received, "time", None)
        response_time_ms = None
        if sent_time is not None and received_time is not None:
            response_time_ms = max(
                0.0, (float(received_time) - float(sent_time)) * 1000
            )
        records.append(
            DiscoveryRecord(
                address=address,
                mac_address=str(received.hwsrc),
                response_time_ms=response_time_ms,
            )
        )
    return records


def _npcap_library_present() -> bool:
    """Check common Npcap/WinPcap locations without running external commands."""
    windows_root = Path(os.environ.get("WINDIR", r"C:\\Windows"))
    known_paths = (
        windows_root / "System32" / "Npcap" / "npcap.dll",
        windows_root / "System32" / "Npcap" / "wpcap.dll",
        windows_root / "System32" / "wpcap.dll",
        windows_root / "SysWOW64" / "wpcap.dll",
    )
    return any(path.is_file() for path in known_paths) or any(
        ctypes.util.find_library(name) for name in ("npcap", "wpcap")
    )
