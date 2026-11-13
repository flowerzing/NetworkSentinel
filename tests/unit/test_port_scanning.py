"""Tests for authorized TCP scan orchestration and bounded probing."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import UUID, uuid4

import pytest

from netsentinel.application.authorization import AuthorizationService
from netsentinel.application.control import CancellationToken, RateLimiter
from netsentinel.application.events import ProgressEvent
from netsentinel.application.policies import SafetyPolicy
from netsentinel.application.port_scanning import PortScanService
from netsentinel.domain.enums import JobState, OperationType
from netsentinel.domain.errors import (
    AuthorizationError,
    OperationCancelled,
    PolicyViolation,
)
from netsentinel.domain.models import Job, PortObservation
from netsentinel.domain.validation import parse_scope
from netsentinel.infrastructure.scanning.tcp_scanner import TcpConnectScanner


class FakePortScanAdapter:
    def __init__(self, observations: tuple[PortObservation, ...]) -> None:
        self.observations = observations
        self.calls = 0
        self.received_hosts = ()
        self.received_ports = ()

    def scan(
        self,
        hosts,
        ports,
        *,
        timeout_seconds,
        max_concurrency,
        rate_limiter,
        cancellation,
        job_id,
        progress,
    ):
        self.calls += 1
        self.received_hosts = hosts
        self.received_ports = ports
        if progress is not None:
            for completed, observation in enumerate(self.observations, start=1):
                progress(
                    ProgressEvent(
                        job_id=job_id,
                        completed=completed,
                        total=len(hosts) * len(ports),
                        message=f"fake {observation.address}:{observation.port}",
                    )
                )
        return self.observations


class FakePortScanRepository:
    def __init__(self) -> None:
        self.jobs: list[Job] = []
        self.observations: list[tuple[PortObservation, UUID | None]] = []
        self.audit_events = []

    def save_job(self, job: Job) -> None:
        self.jobs.append(job)

    def save_port_observation(self, observation, job_id=None) -> None:
        self.observations.append((observation, job_id))

    def append_audit_event(self, event) -> None:
        self.audit_events.append(event)


def _authorization(scope):
    now = datetime.now(UTC)
    return AuthorizationService(SafetyPolicy()).confirm(
        operator="operator",
        operation=OperationType.PORT_SCAN,
        scope=scope,
        reason="Authorized lab service inventory",
        confirmed_at=now,
        expires_at=now + timedelta(minutes=10),
    )


def test_tcp_scanner_uses_fake_probe_and_reports_bounded_progress() -> None:
    calls: list[tuple[IPv4Address, int, float]] = []

    def probe(address, port, timeout):
        calls.append((address, port, timeout))
        return "open" if port == 22 else "closed"

    scanner = TcpConnectScanner(probe=probe)
    token = CancellationToken()
    progress: list[ProgressEvent] = []
    job_id = uuid4()

    observations = scanner.scan(
        (IPv4Address("192.168.50.1"), IPv4Address("192.168.50.2")),
        (22, 80),
        timeout_seconds=1.0,
        max_concurrency=2,
        rate_limiter=RateLimiter(1000),
        cancellation=token,
        job_id=job_id,
        progress=progress.append,
    )

    assert len(calls) == 4
    assert [(item.address, item.port, item.state) for item in observations] == [
        (IPv4Address("192.168.50.1"), 22, "open"),
        (IPv4Address("192.168.50.1"), 80, "closed"),
        (IPv4Address("192.168.50.2"), 22, "open"),
        (IPv4Address("192.168.50.2"), 80, "closed"),
    ]
    assert progress[-1].completed == 4
    assert progress[-1].total == 4
    assert all(event.job_id == job_id for event in progress)


def test_tcp_scanner_honors_cancellation_before_submitting_work() -> None:
    token = CancellationToken()
    token.cancel()
    scanner = TcpConnectScanner(probe=lambda address, port, timeout: "open")

    with pytest.raises(OperationCancelled, match="cancelled"):
        scanner.scan(
            (IPv4Address("192.168.50.1"),),
            (22,),
            timeout_seconds=1.0,
            max_concurrency=1,
            rate_limiter=RateLimiter(25),
            cancellation=token,
            job_id=uuid4(),
        )


def test_port_scan_service_persists_jobs_observations_and_audit() -> None:
    scope = parse_scope(["192.168.50.0/30"])
    observed_at = datetime(2026, 1, 1, 12, tzinfo=UTC)
    observations = (
        PortObservation(
            address=IPv4Address("192.168.50.1"),
            port=80,
            protocol="TCP",
            state="OPEN",
            observed_at=observed_at,
        ),
        PortObservation(
            address=IPv4Address("192.168.50.2"),
            port=22,
            protocol="tcp",
            state="closed",
            observed_at=observed_at,
        ),
    )
    adapter = FakePortScanAdapter(observations)
    repository = FakePortScanRepository()
    progress: list[ProgressEvent] = []

    result = PortScanService(SafetyPolicy(), adapter, repository).run(
        scope=scope,
        ports=(22, 80),
        authorization=_authorization(scope),
        progress=progress.append,
    )

    assert adapter.calls == 1
    assert adapter.received_hosts == scope.hosts()
    assert adapter.received_ports == (22, 80)
    assert [item.state for item in result] == ["open", "closed"]
    assert [job.state for job in repository.jobs] == [
        JobState.RUNNING,
        JobState.COMPLETED,
    ]
    assert [item[0] for item in repository.observations] == list(result)
    assert [event.action for event in repository.audit_events] == [
        "port_scan.started",
        "port_scan.completed",
    ]
    assert progress[0].completed == 0
    assert progress[-1].completed == 2


def test_port_scan_service_rejects_adapter_evidence_outside_scope() -> None:
    scope = parse_scope(["192.168.50.1"])
    adapter = FakePortScanAdapter(
        (
            PortObservation(
                address=IPv4Address("192.168.50.2"),
                port=22,
                protocol="tcp",
                state="open",
            ),
        )
    )
    repository = FakePortScanRepository()

    with pytest.raises(PolicyViolation, match="outside the authorized scope"):
        PortScanService(SafetyPolicy(), adapter, repository).run(
            scope=scope,
            ports=(22,),
            authorization=_authorization(scope),
        )

    assert repository.observations == []
    assert repository.jobs[-1].state is JobState.FAILED


def test_port_scan_requires_authorization_before_adapter_call() -> None:
    scope = parse_scope(["192.168.50.1"])
    adapter = FakePortScanAdapter(())

    with pytest.raises(AuthorizationError, match="explicit authorization"):
        PortScanService(SafetyPolicy(), adapter).run(
            scope=scope,
            ports=(22,),
            authorization=None,
        )

    assert adapter.calls == 0
