"""Enumerations shared by the NetSentinel domain."""

from enum import StrEnum


class OperationType(StrEnum):
    """Network operation categories subject to authorization."""

    DISCOVERY = "discovery"
    PORT_SCAN = "port_scan"
    MONITOR = "monitor"


class JobState(StrEnum):
    """Allowed lifecycle states for future background jobs."""

    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class Severity(StrEnum):
    """Evidence-based finding severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceSource(StrEnum):
    """Sources from which normalized evidence can originate."""

    SCAPY = "scapy"
    SOCKET = "socket"
    NMAP = "nmap"
    SYSTEM = "system"
    USER = "user"
