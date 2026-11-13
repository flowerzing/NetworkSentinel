"""Tests for authorized discovery orchestration and normalization."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

import pytest

from netsentinel.application.authorization import AuthorizationService
from netsentinel.application.discovery import DiscoveryService
from netsentinel.application.policies import SafetyPolicy
from netsentinel.domain.enums import OperationType
from netsentinel.domain.errors import (
    AuthorizationError,
    PolicyViolation,
    ValidationError,
)
from netsentinel.domain.models import DiscoveryRecord
from netsentinel.domain.validation import parse_scope
from netsentinel.infrastructure.scanning.scapy_discovery import diagnose_scapy


class FakeDiscoveryAdapter:
    def __init__(self, records: tuple[DiscoveryRecord, ...]) -> None:
        self.records = records
        self.calls = 0

    def discover(self, scope, *, interface=None, cancellation=None):
        self.calls += 1
        return self.records


class FakeRepository:
    def __init__(self) -> None:
        self.assets = []
        self.audit_events = []

    def save_asset(self, asset) -> None:
        self.assets.append(asset)

    def append_audit_event(self, event) -> None:
        self.audit_events.append(event)


def _authorization(scope):
    now = datetime.now(UTC)
    return AuthorizationService(SafetyPolicy()).confirm(
        operator="operator",
        operation=OperationType.DISCOVERY,
        scope=scope,
        reason="Authorized lab inventory",
        confirmed_at=now,
        expires_at=now + timedelta(minutes=10),
    )


def test_scapy_capability_check_returns_diagnostics_without_running_discovery() -> None:
    capability = diagnose_scapy()

    assert capability.scapy_available is True
    assert capability.message
    assert capability.available is capability.npcap_available


def test_discovery_normalizes_deduplicates_and_persists_assets() -> None:
    scope = parse_scope(["192.168.50.0/30"])
    observed_at = datetime(2026, 1, 1, 12, tzinfo=UTC)
    adapter = FakeDiscoveryAdapter(
        (
            DiscoveryRecord(
                address=IPv4Address("192.168.50.1"),
                mac_address="aa-bb-cc-dd-ee-ff",
                hostname=" lab-device ",
                response_time_ms=2.5,
                observed_at=observed_at,
            ),
            DiscoveryRecord(
                address=IPv4Address("192.168.50.1"),
                vendor=" Example Vendor ",
                observed_at=observed_at + timedelta(seconds=1),
            ),
        )
    )
    repository = FakeRepository()

    assets = DiscoveryService(SafetyPolicy(), adapter, repository).run(
        scope=scope,
        authorization=_authorization(scope),
        interface="Ethernet",
    )

    assert adapter.calls == 1
    assert len(assets) == 1
    assert assets[0].mac_address == "AA:BB:CC:DD:EE:FF"
    assert assets[0].hostname == "lab-device"
    assert assets[0].vendor == "Example Vendor"
    assert assets[0].response_time_ms == 2.5
    assert repository.assets == list(assets)
    assert [event.action for event in repository.audit_events] == [
        "discovery.started",
        "discovery.completed",
    ]


def test_discovery_rejects_adapter_results_outside_authorized_scope() -> None:
    scope = parse_scope(["192.168.50.1"])
    adapter = FakeDiscoveryAdapter(
        (DiscoveryRecord(address=IPv4Address("192.168.50.2")),)
    )
    repository = FakeRepository()

    with pytest.raises(PolicyViolation, match="outside the authorized scope"):
        DiscoveryService(SafetyPolicy(), adapter, repository).run(
            scope=scope,
            authorization=_authorization(scope),
        )

    assert repository.assets == []
    assert repository.audit_events[-1].action == "discovery.failed"


def test_discovery_rejects_missing_authorization_before_adapter_call() -> None:
    scope = parse_scope(["192.168.50.1"])
    adapter = FakeDiscoveryAdapter(())

    with pytest.raises(AuthorizationError, match="explicit authorization"):
        DiscoveryService(SafetyPolicy(), adapter).run(
            scope=scope,
            authorization=None,
        )

    assert adapter.calls == 0


def test_discovery_rejects_invalid_adapter_evidence() -> None:
    scope = parse_scope(["192.168.50.1"])
    adapter = FakeDiscoveryAdapter(
        (
            DiscoveryRecord(
                address=IPv4Address("192.168.50.1"),
                response_time_ms=-1,
            ),
        )
    )

    with pytest.raises(ValidationError, match="response time"):
        DiscoveryService(SafetyPolicy(), adapter).run(
            scope=scope,
            authorization=_authorization(scope),
        )
