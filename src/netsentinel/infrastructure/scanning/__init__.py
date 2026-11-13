"""Adapters for bounded network discovery and service detection."""

from netsentinel.infrastructure.scanning.nmap_services import (
    NmapCapability,
    NmapServicesAdapter,
    build_nmap_command,
    diagnose_nmap,
    parse_nmap_xml,
)
from netsentinel.infrastructure.scanning.scapy_discovery import (
    ScapyCapability,
    ScapyDiscoveryAdapter,
    diagnose_scapy,
)
from netsentinel.infrastructure.scanning.tcp_scanner import TcpConnectScanner

__all__ = [
    "NmapCapability",
    "NmapServicesAdapter",
    "ScapyCapability",
    "ScapyDiscoveryAdapter",
    "TcpConnectScanner",
    "build_nmap_command",
    "diagnose_nmap",
    "diagnose_scapy",
    "parse_nmap_xml",
]
