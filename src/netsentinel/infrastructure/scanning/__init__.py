"""Adapters for bounded network discovery and service detection."""

from netsentinel.infrastructure.scanning.scapy_discovery import (
    ScapyCapability,
    ScapyDiscoveryAdapter,
    diagnose_scapy,
)
from netsentinel.infrastructure.scanning.tcp_scanner import TcpConnectScanner

__all__ = [
    "ScapyCapability",
    "ScapyDiscoveryAdapter",
    "TcpConnectScanner",
    "diagnose_scapy",
]
