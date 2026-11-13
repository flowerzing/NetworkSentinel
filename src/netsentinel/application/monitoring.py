"""Application service for local interface and traffic monitoring."""

from __future__ import annotations

from datetime import UTC, datetime
from math import isfinite
from typing import Protocol

from netsentinel.domain.errors import ValidationError
from netsentinel.domain.models import (
    InterfaceInfo,
    MonitorSnapshot,
    TrafficCounters,
    TrafficSample,
)


class MonitorProvider(Protocol):
    """Provider contract for operating-system network telemetry."""

    def interfaces(self) -> tuple[InterfaceInfo, ...]:
        """Return normalized local interface metadata."""

    def traffic(self) -> tuple[TrafficCounters, ...]:
        """Return cumulative counters without calculating rates."""


class NetworkMonitorService:
    """Normalize provider data and calculate rates between local samples."""

    def __init__(self, provider: MonitorProvider) -> None:
        self._provider = provider
        self._previous: dict[str, TrafficSample] = {}

    def refresh(self, sampled_at: datetime | None = None) -> MonitorSnapshot:
        """Read one provider snapshot and calculate per-interface byte rates."""
        timestamp = sampled_at or datetime.now(UTC)
        _validate_timestamp(timestamp)
        interfaces = _normalize_interfaces(self._provider.interfaces())
        counters = _normalize_counters(self._provider.traffic())
        traffic = tuple(
            _sample_counter(
                counter,
                self._previous.get(counter.interface_name),
                timestamp,
            )
            for counter in counters
        )
        self._previous = {sample.interface_name: sample for sample in traffic}
        return MonitorSnapshot(
            sampled_at=timestamp.astimezone(UTC),
            interfaces=interfaces,
            traffic=traffic,
        )

    def reset(self) -> None:
        """Forget the previous sample so the next refresh starts at zero rate."""
        self._previous.clear()


def _validate_timestamp(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError("Monitor sample time must include a timezone")


def _normalize_interfaces(
    interfaces: tuple[InterfaceInfo, ...],
) -> tuple[InterfaceInfo, ...]:
    normalized: list[InterfaceInfo] = []
    seen: set[str] = set()
    for interface in interfaces:
        name = interface.name.strip()
        if not name:
            raise ValidationError("Network interface name cannot be empty")
        if name in seen:
            raise ValidationError(f"Duplicate network interface: {name!r}")
        if interface.speed_mbps is not None and (
            not isfinite(interface.speed_mbps) or interface.speed_mbps < 0
        ):
            raise ValidationError("Interface speed must be finite and non-negative")
        if interface.mtu is not None and interface.mtu < 1:
            raise ValidationError("Interface MTU must be positive")
        seen.add(name)
        normalized.append(
            InterfaceInfo(
                name=name,
                ipv4_addresses=interface.ipv4_addresses,
                is_up=interface.is_up,
                speed_mbps=interface.speed_mbps,
                mtu=interface.mtu,
            )
        )
    return tuple(normalized)


def _normalize_counters(
    counters: tuple[TrafficCounters, ...],
) -> tuple[TrafficCounters, ...]:
    normalized: list[TrafficCounters] = []
    seen: set[str] = set()
    for counter in counters:
        name = counter.interface_name.strip()
        if not name:
            raise ValidationError("Traffic counter interface name cannot be empty")
        if name in seen:
            raise ValidationError(f"Duplicate traffic counters: {name!r}")
        values = (
            counter.bytes_sent,
            counter.bytes_received,
            counter.packets_sent,
            counter.packets_received,
            counter.errors_in,
            counter.errors_out,
            counter.drops_in,
            counter.drops_out,
        )
        if any(value < 0 for value in values):
            raise ValidationError("Traffic counters cannot be negative")
        seen.add(name)
        normalized.append(
            TrafficCounters(
                interface_name=name,
                bytes_sent=counter.bytes_sent,
                bytes_received=counter.bytes_received,
                packets_sent=counter.packets_sent,
                packets_received=counter.packets_received,
                errors_in=counter.errors_in,
                errors_out=counter.errors_out,
                drops_in=counter.drops_in,
                drops_out=counter.drops_out,
            )
        )
    return tuple(normalized)


def _sample_counter(
    counter: TrafficCounters,
    previous: TrafficSample | None,
    sampled_at: datetime,
) -> TrafficSample:
    send_rate = 0.0
    receive_rate = 0.0
    if previous is not None:
        elapsed = (sampled_at - previous.sampled_at).total_seconds()
        if elapsed > 0:
            if counter.bytes_sent >= previous.bytes_sent:
                send_rate = (counter.bytes_sent - previous.bytes_sent) / elapsed
            if counter.bytes_received >= previous.bytes_received:
                receive_rate = (
                    counter.bytes_received - previous.bytes_received
                ) / elapsed

    return TrafficSample(
        interface_name=counter.interface_name,
        sampled_at=sampled_at.astimezone(UTC),
        bytes_sent=counter.bytes_sent,
        bytes_received=counter.bytes_received,
        packets_sent=counter.packets_sent,
        packets_received=counter.packets_received,
        send_rate_bytes_per_second=send_rate,
        receive_rate_bytes_per_second=receive_rate,
        errors_in=counter.errors_in,
        errors_out=counter.errors_out,
        drops_in=counter.drops_in,
        drops_out=counter.drops_out,
    )
