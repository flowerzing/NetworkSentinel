"""Parameterized SQLite repositories for normalized domain records."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import Any
from uuid import UUID

from netsentinel.domain.enums import EvidenceSource, JobState, OperationType, Severity
from netsentinel.domain.models import (
    AssessmentFinding,
    AuditEvent,
    AuthorizationRecord,
    DeviceAsset,
    Job,
    PortObservation,
)
from netsentinel.domain.validation import parse_scope
from netsentinel.infrastructure.database.connection import SQLiteDatabase


class SQLiteRepository:
    """Persist domain objects using short-lived parameterized transactions."""

    def __init__(self, database: SQLiteDatabase) -> None:
        self._database = database
        self._database.initialize()

    def save_authorization(self, record: AuthorizationRecord) -> None:
        """Insert or replace one authorization record."""
        with self._database.connection() as connection:
            connection.execute(
                """
                INSERT INTO authorization_records
                    (record_id, operator, operation, reason, scope_json,
                     confirmed_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(record_id) DO UPDATE SET
                    operator = excluded.operator,
                    operation = excluded.operation,
                    reason = excluded.reason,
                    scope_json = excluded.scope_json,
                    confirmed_at = excluded.confirmed_at,
                    expires_at = excluded.expires_at
                """,
                (
                    str(record.record_id),
                    record.operator,
                    record.operation.value,
                    record.reason,
                    _scope_json(record),
                    _datetime_text(record.confirmed_at),
                    _datetime_text(record.expires_at),
                ),
            )

    def get_authorization(self, record_id: UUID) -> AuthorizationRecord | None:
        """Load one authorization record by its stable identifier."""
        with self._database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM authorization_records WHERE record_id = ?",
                (str(record_id),),
            ).fetchone()
        if row is None:
            return None
        scope_data = json.loads(row["scope_json"])
        return AuthorizationRecord(
            record_id=UUID(row["record_id"]),
            operator=row["operator"],
            operation=OperationType(row["operation"]),
            scope=parse_scope(scope_data["targets"], scope_data["exclusions"]),
            reason=row["reason"],
            confirmed_at=_parse_datetime(row["confirmed_at"]),
            expires_at=_parse_datetime(row["expires_at"]),
        )

    def save_job(self, job: Job) -> None:
        """Persist a job lifecycle snapshot."""
        with self._database.connection() as connection:
            connection.execute(
                """
                INSERT INTO jobs
                    (job_id, operation, state, authorization_id, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    operation = excluded.operation,
                    state = excluded.state,
                    authorization_id = excluded.authorization_id,
                    created_at = excluded.created_at
                """,
                (
                    str(job.job_id),
                    job.operation.value,
                    job.state.value,
                    str(job.authorization_id),
                    _datetime_text(job.created_at),
                ),
            )

    def get_job(self, job_id: UUID) -> Job | None:
        """Load one job lifecycle snapshot."""
        with self._database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (str(job_id),)
            ).fetchone()
        if row is None:
            return None
        return Job(
            job_id=UUID(row["job_id"]),
            operation=OperationType(row["operation"]),
            state=JobState(row["state"]),
            created_at=_parse_datetime(row["created_at"]),
            authorization_id=UUID(row["authorization_id"]),
        )

    def save_asset(self, asset: DeviceAsset) -> None:
        """Insert or update an inventory record without erasing known fields."""
        with self._database.connection() as connection:
            connection.execute(
                """
                INSERT INTO assets
                    (asset_id, ip_address, mac_address, hostname, vendor,
                     response_time_ms, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    mac_address = COALESCE(excluded.mac_address, assets.mac_address),
                    hostname = COALESCE(excluded.hostname, assets.hostname),
                    vendor = COALESCE(excluded.vendor, assets.vendor),
                    response_time_ms = COALESCE(
                        excluded.response_time_ms, assets.response_time_ms
                    ),
                    last_seen = excluded.last_seen,
                    status = excluded.status
                """,
                (
                    str(asset.asset_id),
                    str(asset.address),
                    asset.mac_address,
                    asset.hostname,
                    asset.vendor,
                    asset.response_time_ms,
                    _datetime_text(asset.first_seen),
                    _datetime_text(asset.last_seen),
                    asset.status,
                ),
            )

    def list_assets(self, search: str | None = None) -> tuple[DeviceAsset, ...]:
        """Return inventory records, optionally filtered by address or hostname."""
        with self._database.connection() as connection:
            if search:
                pattern = f"%{search.strip()}%"
                rows = connection.execute(
                    """
                    SELECT * FROM assets
                    WHERE ip_address LIKE ? OR hostname LIKE ? OR mac_address LIKE ?
                    ORDER BY last_seen DESC
                    """,
                    (pattern, pattern, pattern),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM assets ORDER BY last_seen DESC"
                ).fetchall()
        return tuple(_asset_from_row(row) for row in rows)

    def save_port_observation(
        self,
        observation: PortObservation,
        job_id: UUID | None = None,
    ) -> None:
        """Persist one normalized port observation."""
        with self._database.connection() as connection:
            connection.execute(
                """
                INSERT INTO port_observations
                    (observation_id, job_id, address, port, protocol, state,
                     service, version, source, observed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(observation_id) DO UPDATE SET
                    job_id = excluded.job_id,
                    address = excluded.address,
                    port = excluded.port,
                    protocol = excluded.protocol,
                    state = excluded.state,
                    service = excluded.service,
                    version = excluded.version,
                    source = excluded.source,
                    observed_at = excluded.observed_at
                """,
                (
                    str(observation.observation_id),
                    str(job_id) if job_id else None,
                    str(observation.address),
                    observation.port,
                    observation.protocol,
                    observation.state,
                    observation.service,
                    observation.version,
                    observation.source.value,
                    _datetime_text(observation.observed_at),
                ),
            )

    def list_port_observations(
        self, job_id: UUID | None = None
    ) -> tuple[PortObservation, ...]:
        """Return normalized port observations, optionally scoped to a job."""
        with self._database.connection() as connection:
            if job_id is None:
                rows = connection.execute(
                    "SELECT * FROM port_observations ORDER BY observed_at"
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM port_observations
                    WHERE job_id = ? ORDER BY observed_at
                    """,
                    (str(job_id),),
                ).fetchall()
        return tuple(_port_from_row(row) for row in rows)

    def save_finding(
        self, finding: AssessmentFinding, job_id: UUID | None = None
    ) -> None:
        """Persist an evidence-linked assessment finding."""
        with self._database.connection() as connection:
            connection.execute(
                """
                INSERT INTO assessment_findings
                    (finding_id, job_id, rule_id, severity, title, explanation,
                     recommendation, confidence, evidence_ids_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    job_id = excluded.job_id,
                    rule_id = excluded.rule_id,
                    severity = excluded.severity,
                    title = excluded.title,
                    explanation = excluded.explanation,
                    recommendation = excluded.recommendation,
                    confidence = excluded.confidence,
                    evidence_ids_json = excluded.evidence_ids_json
                """,
                (
                    str(finding.finding_id),
                    str(job_id) if job_id else None,
                    finding.rule_id,
                    finding.severity.value,
                    finding.title,
                    finding.explanation,
                    finding.recommendation,
                    finding.confidence,
                    json.dumps([str(value) for value in finding.evidence_ids]),
                ),
            )

    def list_findings(
        self, job_id: UUID | None = None
    ) -> tuple[AssessmentFinding, ...]:
        """Return evidence-linked findings, optionally scoped to a job."""
        with self._database.connection() as connection:
            if job_id is None:
                rows = connection.execute(
                    "SELECT * FROM assessment_findings ORDER BY finding_id"
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM assessment_findings
                    WHERE job_id = ? ORDER BY finding_id
                    """,
                    (str(job_id),),
                ).fetchall()
        return tuple(_finding_from_row(row) for row in rows)

    def append_audit_event(self, event: AuditEvent) -> None:
        """Append an immutable audit event."""
        with self._database.connection() as connection:
            connection.execute(
                """
                INSERT INTO audit_events
                    (event_id, action, occurred_at, operator, operation,
                     authorization_id, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(event.event_id),
                    event.action,
                    _datetime_text(event.occurred_at),
                    event.operator,
                    event.operation.value if event.operation else None,
                    str(event.authorization_id) if event.authorization_id else None,
                    json.dumps(list(event.details)),
                ),
            )


def _scope_json(record: AuthorizationRecord) -> str:
    return json.dumps(
        {
            "targets": [str(value) for value in record.scope.targets],
            "exclusions": [str(value) for value in record.scope.exclusions],
        },
        separators=(",", ":"),
    )


def _datetime_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Persisted datetimes must include a timezone")
    return value.astimezone(UTC).isoformat()


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Stored datetime is missing a timezone")
    return parsed.astimezone(UTC)


def _asset_from_row(row: Any) -> DeviceAsset:
    return DeviceAsset(
        asset_id=UUID(row["asset_id"]),
        address=IPv4Address(row["ip_address"]),
        first_seen=_parse_datetime(row["first_seen"]),
        last_seen=_parse_datetime(row["last_seen"]),
        mac_address=row["mac_address"],
        hostname=row["hostname"],
        vendor=row["vendor"],
        response_time_ms=row["response_time_ms"],
        status=row["status"],
    )


def _port_from_row(row: Any) -> PortObservation:
    return PortObservation(
        observation_id=UUID(row["observation_id"]),
        address=IPv4Address(row["address"]),
        port=row["port"],
        protocol=row["protocol"],
        state=row["state"],
        service=row["service"],
        version=row["version"],
        source=EvidenceSource(row["source"]),
        observed_at=_parse_datetime(row["observed_at"]),
    )


def _finding_from_row(row: Any) -> AssessmentFinding:
    return AssessmentFinding(
        finding_id=UUID(row["finding_id"]),
        rule_id=row["rule_id"],
        severity=Severity(row["severity"]),
        title=row["title"],
        explanation=row["explanation"],
        recommendation=row["recommendation"],
        confidence=row["confidence"],
        evidence_ids=tuple(
            UUID(value) for value in json.loads(row["evidence_ids_json"])
        ),
    )
