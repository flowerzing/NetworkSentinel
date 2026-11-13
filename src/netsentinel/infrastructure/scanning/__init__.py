"""Adapters for bounded network discovery and service detection."""

from netsentinel.infrastructure.scanning.scapy_discovery import (
    ScapyCapability,
    ScapyDiscoveryAdapter,
    diagnose_scapy,
)

__all__ = ["ScapyCapability", "ScapyDiscoveryAdapter", "diagnose_scapy"]
