"""psutil adapter for local interface metadata and traffic counters."""

from __future__ import annotations

import socket
from collections.abc import Iterable
from ipaddress import IPv4Address
from typing import Any

import psutil  # type: ignore[import-untyped]

from netsentinel.domain.models import InterfaceInfo, TrafficCounters


class PsutilMonitorProvider:
    """Read local interface state and cumulative counters through psutil."""

    def interfaces(self) -> tuple[InterfaceInfo, ...]:
        """Return interface metadata without generating network traffic."""
        stats = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()
        names = sorted(set(stats) | set(addresses))
        result: list[InterfaceInfo] = []
        for name in names:
            stat = stats.get(name)
            result.append(
                InterfaceInfo(
                    name=name,
                    ipv4_addresses=_ipv4_addresses(addresses.get(name, ())),
                    is_up=bool(stat.isup) if stat is not None else False,
                    speed_mbps=(
                        float(stat.speed)
                        if stat is not None and stat.speed > 0
                        else None
                    ),
                    mtu=stat.mtu if stat is not None and stat.mtu > 0 else None,
                )
            )
        return tuple(result)

    def traffic(self) -> tuple[TrafficCounters, ...]:
        """Return cumulative counters for each interface."""
        counters = psutil.net_io_counters(pernic=True) or {}
        return tuple(
            TrafficCounters(
                interface_name=name,
                bytes_sent=int(counter.bytes_sent),
                bytes_received=int(counter.bytes_recv),
                packets_sent=int(counter.packets_sent),
                packets_received=int(counter.packets_recv),
                errors_in=int(counter.errin),
                errors_out=int(counter.errout),
                drops_in=int(counter.dropin),
                drops_out=int(counter.dropout),
            )
            for name, counter in sorted(counters.items())
        )


def _ipv4_addresses(values: Iterable[Any]) -> tuple[IPv4Address, ...]:
    """Extract IPv4 addresses and ignore IPv6/link-layer provider records."""
    result: list[IPv4Address] = []
    for value in values:
        if value.family != socket.AF_INET:
            continue
        try:
            result.append(IPv4Address(str(value.address).split("%", 1)[0]))
        except ValueError:
            continue
    return tuple(result)
