"""Authorized network discovery orchestration and normalization."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from ipaddress import IPv4Address
from math import isfinite
from typing import Protocol
from uuid import uuid4

from netsentinel.application.control import CancellationToken
from netsentinel.application.policies import SafetyPolicy
from netsentinel.domain.enums import OperationType
from netsentinel.domain.errors import (
    OperationCancelled,
    PolicyViolation,
    ValidationError,
)
from netsentinel.domain.models import (
    AuditEvent,
    AuthorizationRecord,
    DeviceAsset,
    DiscoveryRecord,
    ScanScope,
)


class DiscoveryAdapter(Protocol):
    """Adapter contract for a bounded, authorized discovery implementation."""

    def discover(
        self,
        scope: ScanScope,
        *,
        interface: str | None = None,
        cancellation: CancellationToken | None = None,
    ) -> Iterable[DiscoveryRecord]:
        """Return raw discovery evidence for the already-authorized scope."""


class DiscoveryRepository(Protocol):
    """Persistence operations needed by the discovery use case."""

    def save_asset(self, asset: DeviceAsset) -> None:
        """Upsert one normalized device asset."""

    def append_audit_event(self, event: AuditEvent) -> None:
        """Append an immutable operation event."""


class DiscoveryService:
    """Validate, execute, normalize, and persist one discovery operation."""

    def __init__(
        self,
        policy: SafetyPolicy,
        adapter: DiscoveryAdapter,
        repository: DiscoveryRepository | None = None,
    ) -> None:
        self._policy = policy
        self._adapter = adapter
        self._repository = repository

    def run(
        self,
        *,
        scope: ScanScope,
        authorization: AuthorizationRecord | None,
        interface: str | None = None,
        cancellation: CancellationToken | None = None,
    ) -> tuple[DeviceAsset, ...]:
        """Run discovery only after policy and authorization validation."""
        self._policy.validate_authorization(
            authorization=authorization,
            operation=OperationType.DISCOVERY,
            scope=scope,
        )
        if authorization is None:  # pragma: no cover - narrowed by the policy call
            raise PolicyViolation("An explicit authorization is required")

        token = cancellation or CancellationToken()
        self._record_audit(
            authorization,
            action="discovery.started",
            details=(
                ("target_count", str(len(scope.hosts()))),
                ("interface", interface or "default"),
            ),
        )
        try:
            token.raise_if_cancelled()
            records = tuple(
                normalize_discovery_record(record, scope)
                for record in self._adapter.discover(
                    scope,
                    interface=interface,
                    cancellation=token,
                )
            )
            token.raise_if_cancelled()
            assets = tuple(
                _asset_from_record(record) for record in _merge_records(records)
            )
            if self._repository is not None:
                for asset in assets:
                    self._repository.save_asset(asset)
                self._record_audit(
                    authorization,
                    action="discovery.completed",
                    details=(("result_count", str(len(assets))),),
                )
            return assets
        except OperationCancelled:
            self._record_audit(
                authorization,
                action="discovery.cancelled",
                details=(),
            )
            raise
        except Exception as exc:
            self._record_audit(
                authorization,
                action="discovery.failed",
                details=(("error_type", type(exc).__name__),),
            )
            raise

    def _record_audit(
        self,
        authorization: AuthorizationRecord,
        *,
        action: str,
        details: tuple[tuple[str, str], ...],
    ) -> None:
        if self._repository is None:
            return
        self._repository.append_audit_event(
            AuditEvent(
                event_id=uuid4(),
                action=action,
                occurred_at=datetime.now(UTC),
                operator=authorization.operator,
                operation=OperationType.DISCOVERY,
                authorization_id=authorization.record_id,
                details=details,
            )
        )


def normalize_discovery_record(
    record: DiscoveryRecord,
    scope: ScanScope,
) -> DiscoveryRecord:
    """Normalize adapter output and reject evidence outside the authorized scope."""
    if not scope.contains_address(record.address):
        raise PolicyViolation(
            f"Discovery adapter returned an address outside the authorized scope: "
            f"{record.address}"
        )
    if record.response_time_ms is not None and (
        not isfinite(record.response_time_ms) or record.response_time_ms < 0
    ):
        raise ValidationError("Discovery response time must be finite and non-negative")
    if record.status not in {"active", "inactive", "unknown"}:
        raise ValidationError(f"Unsupported discovery status: {record.status!r}")
    if record.observed_at.tzinfo is None or record.observed_at.utcoffset() is None:
        raise ValidationError("Discovery observation time must include a timezone")

    return DiscoveryRecord(
        address=record.address,
        mac_address=_normalize_mac(record.mac_address),
        hostname=_normalize_text(record.hostname),
        vendor=_normalize_text(record.vendor),
        response_time_ms=record.response_time_ms,
        status=record.status,
        source=record.source,
        observed_at=record.observed_at.astimezone(UTC),
    )


def _normalize_mac(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    candidate = value.strip().replace("-", ":").replace(".", "")
    if ":" not in candidate and len(candidate) == 12:
        candidate = ":".join(
            candidate[index : index + 2] for index in range(0, 12, 2)
        )
    parts = candidate.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        raise ValidationError(f"Invalid MAC address: {value!r}")
    try:
        normalized = ":".join(f"{int(part, 16):02X}" for part in parts)
    except ValueError as exc:
        raise ValidationError(f"Invalid MAC address: {value!r}") from exc
    return normalized


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _merge_records(records: tuple[DiscoveryRecord, ...]) -> tuple[DiscoveryRecord, ...]:
    """Deduplicate addresses while retaining the newest known evidence."""
    merged: dict[IPv4Address, DiscoveryRecord] = {}
    for record in records:
        previous = merged.get(record.address)
        if previous is None:
            merged[record.address] = record
            continue
        merged[record.address] = DiscoveryRecord(
            address=record.address,
            mac_address=record.mac_address or previous.mac_address,
            hostname=record.hostname or previous.hostname,
            vendor=record.vendor or previous.vendor,
            response_time_ms=(
                record.response_time_ms
                if record.response_time_ms is not None
                else previous.response_time_ms
            ),
            status="active"
            if "active" in {previous.status, record.status}
            else record.status,
            source=record.source,
            observed_at=max(previous.observed_at, record.observed_at),
        )
    return tuple(merged.values())


def _asset_from_record(record: DiscoveryRecord) -> DeviceAsset:
    """Convert one normalized observation into the inventory persistence model."""
    observed_at = record.observed_at.astimezone(UTC)
    return DeviceAsset(
        asset_id=uuid4(),
        address=record.address,
        first_seen=observed_at,
        last_seen=observed_at,
        mac_address=record.mac_address,
        hostname=record.hostname,
        vendor=record.vendor,
        response_time_ms=record.response_time_ms,
        status=record.status,
    )
