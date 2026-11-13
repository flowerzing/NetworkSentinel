"""Tests for local interface monitoring without real network traffic."""

import socket
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from types import SimpleNamespace

import psutil
import pytest

from netsentinel.application.monitoring import NetworkMonitorService
from netsentinel.domain.errors import ValidationError
from netsentinel.domain.models import InterfaceInfo, TrafficCounters
from netsentinel.infrastructure.monitoring.psutil_monitor import PsutilMonitorProvider


class FakeMonitorProvider:
    def __init__(self, counters: tuple[TrafficCounters, ...]) -> None:
        self._counters = counters

    def interfaces(self) -> tuple[InterfaceInfo, ...]:
        return (
            InterfaceInfo(
                name="Ethernet",
                ipv4_addresses=(IPv4Address("192.168.1.10"),),
                is_up=True,
                speed_mbps=1000.0,
                mtu=1500,
            ),
        )

    def traffic(self) -> tuple[TrafficCounters, ...]:
        return self._counters


def _counters(sent: int, received: int) -> tuple[TrafficCounters, ...]:
    return (
        TrafficCounters(
            interface_name="Ethernet",
            bytes_sent=sent,
            bytes_received=received,
            packets_sent=10,
            packets_received=20,
        ),
    )


def test_monitor_calculates_rates_between_samples() -> None:
    provider = FakeMonitorProvider(_counters(1000, 2000))
    service = NetworkMonitorService(provider)
    first = datetime(2026, 1, 1, 12, tzinfo=UTC)

    initial = service.refresh(first)
    provider._counters = _counters(3000, 3000)
    current = service.refresh(first + timedelta(seconds=2))

    assert initial.traffic[0].send_rate_bytes_per_second == 0.0
    assert initial.traffic[0].receive_rate_bytes_per_second == 0.0
    assert current.traffic[0].send_rate_bytes_per_second == 1000.0
    assert current.traffic[0].receive_rate_bytes_per_second == 500.0
    assert current.interfaces[0].ipv4_addresses == (IPv4Address("192.168.1.10"),)


def test_monitor_treats_counter_reset_as_zero_rate() -> None:
    provider = FakeMonitorProvider(_counters(5000, 5000))
    service = NetworkMonitorService(provider)
    first = datetime(2026, 1, 1, 12, tzinfo=UTC)
    service.refresh(first)
    provider._counters = _counters(100, 100)

    current = service.refresh(first + timedelta(seconds=1))

    assert current.traffic[0].send_rate_bytes_per_second == 0.0
    assert current.traffic[0].receive_rate_bytes_per_second == 0.0


def test_monitor_rejects_negative_counters() -> None:
    provider = FakeMonitorProvider(_counters(-1, 0))

    with pytest.raises(ValidationError, match="cannot be negative"):
        NetworkMonitorService(provider).refresh(
            datetime(2026, 1, 1, 12, tzinfo=UTC)
        )


def test_psutil_provider_normalizes_interfaces_and_counters(monkeypatch) -> None:
    monkeypatch.setattr(
        psutil,
        "net_if_stats",
        lambda: {
            "Ethernet": SimpleNamespace(isup=True, speed=100, mtu=1500),
        },
    )
    monkeypatch.setattr(
        psutil,
        "net_if_addrs",
        lambda: {
            "Ethernet": (
                SimpleNamespace(family=socket.AF_INET, address="192.168.1.10"),
                SimpleNamespace(family=socket.AF_INET6, address="fe80::1"),
            ),
        },
    )
    monkeypatch.setattr(
        psutil,
        "net_io_counters",
        lambda pernic=True: {
            "Ethernet": SimpleNamespace(
                bytes_sent=10,
                bytes_recv=20,
                packets_sent=1,
                packets_recv=2,
                errin=0,
                errout=1,
                dropin=2,
                dropout=3,
            ),
        },
    )

    provider = PsutilMonitorProvider()

    assert provider.interfaces()[0].ipv4_addresses == (
        IPv4Address("192.168.1.10"),
    )
    assert provider.traffic()[0].bytes_received == 20
    assert provider.traffic()[0].drops_out == 3
