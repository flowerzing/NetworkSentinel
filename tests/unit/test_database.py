"""Integration-style tests for the local SQLite persistence layer."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import uuid4

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
from netsentinel.infrastructure.database import SQLiteDatabase, SQLiteRepository


def _repository(tmp_path):
    return SQLiteRepository(SQLiteDatabase(tmp_path / "netsentinel.sqlite3"))


def _authorization() -> AuthorizationRecord:
    now = datetime.now(UTC).replace(microsecond=0)
    return AuthorizationRecord.create(
        operator="tester",
        operation=OperationType.PORT_SCAN,
        scope=parse_scope(["192.168.50.0/30"]),
        reason="Controlled test network",
        confirmed_at=now,
        expires_at=now + timedelta(minutes=10),
    )


def test_migrations_are_idempotent(tmp_path) -> None:
    database = SQLiteDatabase(tmp_path / "nested" / "netsentinel.sqlite3")
    repository = SQLiteRepository(database)
    database.initialize()

    with database.connection() as connection:
        version = connection.execute("SELECT version FROM schema_version").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }

    assert version == 2
    assert {"authorization_records", "assets", "audit_events"} <= tables
    assert repository is not None


def test_authorization_and_job_round_trip(tmp_path) -> None:
    repository = _repository(tmp_path)
    authorization = _authorization()
    repository.save_authorization(authorization)
    job = Job(
        job_id=uuid4(),
        operation=OperationType.PORT_SCAN,
        state=JobState.CREATED,
        created_at=authorization.confirmed_at,
        authorization_id=authorization.record_id,
    )
    repository.save_job(job)

    assert repository.get_authorization(authorization.record_id) == authorization
    assert repository.get_job(job.job_id) == job


def test_asset_upsert_preserves_known_fields_and_supports_search(tmp_path) -> None:
    repository = _repository(tmp_path)
    first_seen = datetime(2026, 1, 1, tzinfo=UTC)
    last_seen = datetime(2026, 1, 2, tzinfo=UTC)
    asset_id = uuid4()
    repository.save_asset(
        DeviceAsset(
            asset_id=asset_id,
            address=IPv4Address("192.168.50.2"),
            first_seen=first_seen,
            last_seen=first_seen,
            mac_address="AA:BB:CC:DD:EE:FF",
            hostname="lab-device",
            vendor="Example Vendor",
            response_time_ms=3.5,
            status="active",
        )
    )
    repository.save_asset(
        DeviceAsset(
            asset_id=uuid4(),
            address=IPv4Address("192.168.50.2"),
            first_seen=first_seen,
            last_seen=last_seen,
            status="inactive",
        )
    )

    assets = repository.list_assets("lab-device")
    assert len(assets) == 1
    assert assets[0].asset_id == asset_id
    assert assets[0].mac_address == "AA:BB:CC:DD:EE:FF"
    assert assets[0].response_time_ms == 3.5
    assert assets[0].last_seen == last_seen
    assert assets[0].status == "inactive"


def test_observation_finding_and_audit_round_trip(tmp_path) -> None:
    repository = _repository(tmp_path)
    authorization = _authorization()
    repository.save_authorization(authorization)
    job = Job(
        job_id=uuid4(),
        operation=OperationType.PORT_SCAN,
        state=JobState.COMPLETED,
        created_at=authorization.confirmed_at,
        authorization_id=authorization.record_id,
    )
    repository.save_job(job)
    observation = PortObservation(
        address=IPv4Address("192.168.50.2"),
        port=443,
        protocol="tcp",
        state="open",
        service="https",
        version="Example 1.0",
        source=EvidenceSource.NMAP,
        observed_at=authorization.confirmed_at,
    )
    repository.save_port_observation(observation, job.job_id)
    finding = AssessmentFinding(
        finding_id=uuid4(),
        rule_id="service.metadata",
        severity=Severity.LOW,
        title="Service metadata observed",
        explanation="A service version was reported by the authorized probe.",
        recommendation="Review the service inventory and update policy baselines.",
        confidence=0.8,
        evidence_ids=(observation.observation_id,),
    )
    repository.save_finding(finding, job.job_id)
    audit = AuditEvent(
        event_id=uuid4(),
        action="port_scan.completed",
        occurred_at=authorization.confirmed_at,
        operator=authorization.operator,
        operation=OperationType.PORT_SCAN,
        authorization_id=authorization.record_id,
        details=(("job_id", str(job.job_id)),),
    )
    repository.append_audit_event(audit)

    assert repository.list_port_observations(job.job_id) == (observation,)
    assert repository.list_findings(job.job_id) == (finding,)
    with repository._database.connection() as connection:
        row = connection.execute(
            "SELECT action, operator FROM audit_events WHERE event_id = ?",
            (str(audit.event_id),),
        ).fetchone()
    assert tuple(row) == ("port_scan.completed", "tester")
