"""Immutable domain models used by application services."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from uuid import UUID, uuid4

from netsentinel.domain.enums import EvidenceSource, JobState, OperationType, Severity
from netsentinel.domain.errors import ValidationError


@dataclass(frozen=True, slots=True)
class ScanScope:
    """Normalized IPv4 targets and exclusions for an authorized operation."""

    targets: tuple[IPv4Address | IPv4Network, ...]
    exclusions: tuple[IPv4Address | IPv4Network, ...] = ()

    def hosts(self, limit: int | None = None) -> tuple[IPv4Address, ...]:
        """Return concrete hosts after applying exclusions.

        Target networks are reduced to disjoint integer intervals before
        expansion. ``limit`` therefore bounds both memory and work for large
        or fully excluded networks.
        """
        if limit is not None and limit < 1:
            raise ValueError("host expansion limit must be positive")

        target_ranges = _merge_ranges(_host_ranges(self.targets))
        exclusion_ranges = _merge_ranges(_host_ranges(self.exclusions))
        remaining = _subtract_ranges(target_ranges, exclusion_ranges)
        host_count = sum(end - start + 1 for start, end in remaining)
        if limit is not None and host_count > limit:
            raise ValidationError(f"Scope exceeds the host expansion limit of {limit}")

        return tuple(
            IPv4Address(value)
            for start, end in remaining
            for value in range(start, end + 1)
        )

    def contains(self, other: ScanScope) -> bool:
        """Return whether every concrete host in ``other`` belongs to this scope."""
        return all(self.contains_address(address) for address in other.hosts())

    def contains_address(self, address: IPv4Address) -> bool:
        """Return whether a concrete address is included and not excluded."""
        in_target = any(
            target == address if isinstance(target, IPv4Address) else address in target
            for target in self.targets
        )
        excluded = any(
            exclusion == address
            if isinstance(exclusion, IPv4Address)
            else address in exclusion
            for exclusion in self.exclusions
        )
        return in_target and not excluded


def _host_ranges(
    values: tuple[IPv4Address | IPv4Network, ...],
) -> list[tuple[int, int]]:
    """Convert IPv4 targets to inclusive ranges using host semantics."""
    ranges: list[tuple[int, int]] = []
    for value in values:
        if isinstance(value, IPv4Address):
            number = int(value)
            ranges.append((number, number))
            continue
        if value.prefixlen == 32:
            number = int(value.network_address)
            ranges.append((number, number))
        elif value.prefixlen == 31:
            ranges.append((int(value.network_address), int(value.broadcast_address)))
        else:
            ranges.append(
                (
                    int(value.network_address) + 1,
                    int(value.broadcast_address) - 1,
                )
            )
    return ranges


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping or adjacent inclusive ranges."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def _subtract_ranges(
    targets: list[tuple[int, int]],
    exclusions: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    """Subtract sorted exclusion ranges from sorted target ranges."""
    remaining: list[tuple[int, int]] = []
    for target_start, target_end in targets:
        cursor = target_start
        for exclusion_start, exclusion_end in exclusions:
            if exclusion_end < cursor:
                continue
            if exclusion_start > target_end:
                break
            if exclusion_start > cursor:
                remaining.append((cursor, min(target_end, exclusion_start - 1)))
            cursor = max(cursor, exclusion_end + 1)
            if cursor > target_end:
                break
        if cursor <= target_end:
            remaining.append((cursor, target_end))
    return remaining


@dataclass(frozen=True, slots=True)
class AuthorizationRecord:
    """An operator's time-bounded confirmation for one operation and scope."""

    record_id: UUID
    operator: str
    operation: OperationType
    scope: ScanScope
    reason: str
    confirmed_at: datetime
    expires_at: datetime

    @classmethod
    def create(
        cls,
        *,
        operator: str,
        operation: OperationType,
        scope: ScanScope,
        reason: str,
        expires_at: datetime,
        confirmed_at: datetime | None = None,
    ) -> AuthorizationRecord:
        """Create a normalized authorization record after explicit confirmation."""
        confirmed = confirmed_at or datetime.now(UTC)
        return cls(
            record_id=uuid4(),
            operator=operator.strip(),
            operation=operation,
            scope=scope,
            reason=reason.strip(),
            confirmed_at=confirmed,
            expires_at=expires_at,
        )

    def is_active(self, at: datetime | None = None) -> bool:
        """Return whether the record is valid at the supplied UTC instant."""
        instant = at or datetime.now(UTC)
        return self.confirmed_at <= instant < self.expires_at


@dataclass(frozen=True, slots=True)
class Job:
    """Minimal job identity and lifecycle state for later persistence."""

    job_id: UUID
    operation: OperationType
    state: JobState
    created_at: datetime
    authorization_id: UUID


@dataclass(frozen=True, slots=True)
class PortObservation:
    """A normalized result from a future TCP or Nmap probe."""

    address: IPv4Address
    port: int
    protocol: str
    state: str
    service: str | None = None
    version: str | None = None
    source: EvidenceSource = EvidenceSource.SOCKET
    observation_id: UUID = field(default_factory=uuid4)
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class DeviceAsset:
    """A persistent inventory record for one discovered IPv4 device."""

    asset_id: UUID
    address: IPv4Address
    first_seen: datetime
    last_seen: datetime
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    status: str = "unknown"


@dataclass(frozen=True, slots=True)
class AssessmentFinding:
    """A finding that must remain linked to concrete evidence."""

    finding_id: UUID
    rule_id: str
    severity: Severity
    title: str
    explanation: str
    recommendation: str
    confidence: float
    evidence_ids: tuple[UUID, ...]


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """A record of a user or system action relevant to safety auditing."""

    event_id: UUID
    action: str
    occurred_at: datetime
    operator: str
    operation: OperationType | None
    authorization_id: UUID | None
    details: tuple[tuple[str, str], ...] = ()
