"""Authorized TCP port-scanning orchestration and evidence normalization."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import Protocol
from uuid import UUID, uuid4

from netsentinel.application.control import CancellationToken, RateLimiter
from netsentinel.application.events import ProgressEvent
from netsentinel.application.policies import SafetyPolicy
from netsentinel.domain.enums import JobState, OperationType
from netsentinel.domain.errors import (
    OperationCancelled,
    PolicyViolation,
    ValidationError,
)
from netsentinel.domain.models import (
    AuditEvent,
    AuthorizationRecord,
    Job,
    PortObservation,
    ScanScope,
)

ProgressCallback = Callable[[ProgressEvent], None]


class PortScanAdapter(Protocol):
    """Adapter contract for a bounded TCP port scan implementation."""

    def scan(
        self,
        hosts: tuple[IPv4Address, ...],
        ports: tuple[int, ...],
        *,
        timeout_seconds: float,
        max_concurrency: int,
        rate_limiter: RateLimiter,
        cancellation: CancellationToken,
        job_id: UUID,
        progress: ProgressCallback | None = None,
    ) -> Iterable[PortObservation]:
        """Return one normalized observation for each attempted host and port."""


class PortScanRepository(Protocol):
    """Persistence operations needed by the port-scan use case."""

    def save_job(self, job: Job) -> None:
        """Persist a job lifecycle snapshot."""

    def save_port_observation(
        self, observation: PortObservation, job_id: UUID | None = None
    ) -> None:
        """Persist one port observation."""

    def append_audit_event(self, event: AuditEvent) -> None:
        """Append an immutable operation event."""


class PortScanService:
    """Validate, execute, normalize, and persist one TCP scan operation."""

    def __init__(
        self,
        policy: SafetyPolicy,
        adapter: PortScanAdapter,
        repository: PortScanRepository | None = None,
    ) -> None:
        self._policy = policy
        self._adapter = adapter
        self._repository = repository

    def run(
        self,
        *,
        scope: ScanScope,
        ports: tuple[int, ...],
        authorization: AuthorizationRecord | None,
        cancellation: CancellationToken | None = None,
        job_id: UUID | None = None,
        progress: ProgressCallback | None = None,
    ) -> tuple[PortObservation, ...]:
        """Run a bounded TCP scan only after explicit authorization validation."""
        self._policy.validate_authorization(
            authorization=authorization,
            operation=OperationType.PORT_SCAN,
            scope=scope,
        )
        self._policy.validate_ports(ports)
        if authorization is None:  # pragma: no cover - narrowed by policy validation
            raise PolicyViolation("An explicit authorization is required")

        token = cancellation or CancellationToken()
        scan_job_id = job_id or uuid4()
        created_at = datetime.now(UTC)
        hosts = scope.hosts(limit=self._policy.limits.max_scope_hosts)
        self._save_job(
            scan_job_id,
            authorization,
            created_at=created_at,
            state=JobState.RUNNING,
        )
        self._record_audit(
            authorization,
            action="port_scan.started",
            details=(
                ("job_id", str(scan_job_id)),
                ("host_count", str(len(hosts))),
                ("port_count", str(len(ports))),
            ),
        )
        if progress is not None:
            progress(
                ProgressEvent(
                    job_id=scan_job_id,
                    completed=0,
                    total=len(hosts) * len(ports),
                    message="TCP scan started",
                )
            )

        try:
            token.raise_if_cancelled()
            records = tuple(
                normalize_port_observation(observation, scope, ports)
                for observation in self._adapter.scan(
                    hosts,
                    ports,
                    timeout_seconds=self._policy.limits.connect_timeout_seconds,
                    max_concurrency=self._policy.limits.max_concurrency,
                    rate_limiter=RateLimiter(
                        self._policy.limits.max_rate_per_second
                    ),
                    cancellation=token,
                    job_id=scan_job_id,
                    progress=progress,
                )
            )
            token.raise_if_cancelled()
            observations = _merge_observations(records)
            if self._repository is not None:
                for observation in observations:
                    self._repository.save_port_observation(observation, scan_job_id)
                self._save_job(
                    scan_job_id,
                    authorization,
                    created_at=created_at,
                    state=JobState.COMPLETED,
                )
            self._record_audit(
                authorization,
                action="port_scan.completed",
                details=(
                    ("job_id", str(scan_job_id)),
                    ("result_count", str(len(observations))),
                ),
            )
            return observations
        except OperationCancelled:
            self._save_job(
                scan_job_id,
                authorization,
                created_at=created_at,
                state=JobState.CANCELLED,
            )
            self._record_audit(
                authorization,
                action="port_scan.cancelled",
                details=(("job_id", str(scan_job_id)),),
            )
            raise
        except Exception as exc:
            self._save_job(
                scan_job_id,
                authorization,
                created_at=created_at,
                state=JobState.FAILED,
            )
            self._record_audit(
                authorization,
                action="port_scan.failed",
                details=(
                    ("job_id", str(scan_job_id)),
                    ("error_type", type(exc).__name__),
                ),
            )
            raise

    def _save_job(
        self,
        job_id: UUID,
        authorization: AuthorizationRecord,
        *,
        created_at: datetime,
        state: JobState,
    ) -> None:
        if self._repository is None:
            return
        self._repository.save_job(
            Job(
                job_id=job_id,
                operation=OperationType.PORT_SCAN,
                state=state,
                created_at=created_at,
                authorization_id=authorization.record_id,
            )
        )

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
                operation=OperationType.PORT_SCAN,
                authorization_id=authorization.record_id,
                details=details,
            )
        )


def normalize_port_observation(
    observation: PortObservation,
    scope: ScanScope,
    ports: tuple[int, ...],
) -> PortObservation:
    """Normalize adapter evidence and reject results outside the requested scan."""
    if not scope.contains_address(observation.address):
        raise PolicyViolation(
            "Port adapter returned an address outside the authorized scope: "
            f"{observation.address}"
        )
    if observation.port not in ports:
        raise PolicyViolation(
            f"Port adapter returned an unrequested port: {observation.port}"
        )
    protocol = observation.protocol.strip().lower()
    if protocol != "tcp":
        raise ValidationError("TCP port observations must use the tcp protocol")
    state = observation.state.strip().lower()
    if state not in {"open", "closed", "filtered"}:
        raise ValidationError(f"Unsupported TCP port state: {observation.state!r}")
    if (
        observation.observed_at.tzinfo is None
        or observation.observed_at.utcoffset() is None
    ):
        raise ValidationError("Port observation time must include a timezone")

    return PortObservation(
        observation_id=observation.observation_id,
        address=observation.address,
        port=observation.port,
        protocol=protocol,
        state=state,
        service=_normalize_text(observation.service),
        version=_normalize_text(observation.version),
        source=observation.source,
        observed_at=observation.observed_at.astimezone(UTC),
    )


def _merge_observations(
    observations: tuple[PortObservation, ...],
) -> tuple[PortObservation, ...]:
    """Deduplicate host/port pairs while keeping the newest observation."""
    merged: dict[tuple[IPv4Address, int, str], PortObservation] = {}
    for observation in observations:
        key = (observation.address, observation.port, observation.protocol)
        previous = merged.get(key)
        if previous is None or observation.observed_at >= previous.observed_at:
            merged[key] = observation
    return tuple(merged.values())


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None
