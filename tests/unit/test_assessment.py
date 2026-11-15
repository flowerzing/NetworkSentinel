"""Tests for evidence-based security assessment rules and exports."""

import csv
import json
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from uuid import uuid4

from netsentinel.application.assessment import AssessmentService
from netsentinel.domain.enums import EvidenceSource, Severity
from netsentinel.domain.models import AssessmentFinding, DeviceAsset, PortObservation


class FakeAssessmentRepository:
    def __init__(
        self,
        assets: tuple[DeviceAsset, ...] = (),
        observations: tuple[PortObservation, ...] = (),
    ) -> None:
        self.assets = assets
        self.observations = observations
        self.saved_findings: list[AssessmentFinding] = []
        self.searches: list[str | None] = []
        self.job_ids: list[uuid4 | None] = []

    def list_assets(self, search: str | None = None) -> tuple[DeviceAsset, ...]:
        self.searches.append(search)
        if not search:
            return self.assets
        return tuple(
            asset
            for asset in self.assets
            if search.lower() in str(asset.address).lower()
            or search.lower() in (asset.hostname or "").lower()
            or search.lower() in (asset.mac_address or "").lower()
        )

    def list_port_observations(
        self, job_id: uuid4 | None = None
    ) -> tuple[PortObservation, ...]:
        self.job_ids.append(job_id)
        return self.observations

    def save_finding(
        self, finding: AssessmentFinding, job_id: uuid4 | None = None
    ) -> None:
        self.saved_findings.append(finding)

    def list_findings(
        self, job_id: uuid4 | None = None
    ) -> tuple[AssessmentFinding, ...]:
        return tuple(self.saved_findings)


def _asset(address: str, hostname: str = "") -> DeviceAsset:
    timestamp = datetime(2026, 1, 1, 12, tzinfo=UTC)
    return DeviceAsset(
        asset_id=uuid4(),
        address=IPv4Address(address),
        first_seen=timestamp,
        last_seen=timestamp,
        mac_address="AA:BB:CC:DD:EE:FF",
        hostname=hostname,
        vendor="Example Vendor",
        response_time_ms=2.5,
        status="active",
    )


def _obs(
    address: str,
    port: int,
    state: str = "open",
    service: str | None = None,
    version: str | None = None,
) -> PortObservation:
    return PortObservation(
        observation_id=uuid4(),
        address=IPv4Address(address),
        port=port,
        protocol="tcp",
        state=state,
        service=service,
        version=version,
        source=EvidenceSource.SOCKET,
        observed_at=datetime(2026, 1, 1, 12, tzinfo=UTC),
    )


def test_assessment_generates_findings_for_insecure_services() -> None:
    repository = FakeAssessmentRepository(
        assets=(_asset("192.168.1.10", "lab-host"),),
        observations=(
            _obs("192.168.1.10", 21, service="ftp"),
            _obs("192.168.1.10", 23, service="telnet"),
            _obs("192.168.1.10", 80, service="http"),
        ),
    )
    service = AssessmentService(repository)

    findings = service.assess()

    assert len(findings) >= 2
    rule_ids = {f.rule_id for f in findings}
    assert "insecure_service_exposed" in rule_ids
    # FTP and Telnet should be HIGH severity
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 2
    # HTTP (port 80) should not trigger insecure service rule
    for f in findings:
        if f.rule_id == "insecure_service_exposed":
            assert "21" in f.title or "23" in f.title


def test_assessment_flags_outdated_versions() -> None:
    repository = FakeAssessmentRepository(
        assets=(_asset("192.168.1.10", "web"),),
        observations=(_obs("192.168.1.10", 80, service="apache", version="2.2.15"),),
    )
    service = AssessmentService(repository)

    findings = service.assess()

    outdated = [f for f in findings if f.rule_id == "outdated_service_version"]
    assert len(outdated) == 1
    assert outdated[0].severity == Severity.MEDIUM
    assert "apache" in outdated[0].title.lower()


def test_assessment_flags_high_ports_without_service() -> None:
    repository = FakeAssessmentRepository(
        assets=(_asset("192.168.1.10", "host"),),
        observations=(_obs("192.168.1.10", 50000),),
    )
    service = AssessmentService(repository)

    findings = service.assess()

    high_port = [f for f in findings if f.rule_id == "unusual_high_port_open"]
    assert len(high_port) == 1
    assert high_port[0].severity == Severity.LOW


def test_assessment_flags_many_open_ports() -> None:
    observations = tuple(_obs("192.168.1.10", port) for port in range(1, 15))
    repository = FakeAssessmentRepository(
        assets=(_asset("192.168.1.10", "host"),),
        observations=observations,
    )
    service = AssessmentService(repository)

    findings = service.assess()

    many = [f for f in findings if f.rule_id == "high_open_port_count"]
    assert len(many) == 1
    assert many[0].severity == Severity.LOW
    assert "14" in many[0].title


def test_assessment_exports_csv(tmp_path: Path) -> None:
    findings = (
        AssessmentFinding(
            finding_id=uuid4(),
            rule_id="test_rule",
            severity=Severity.MEDIUM,
            title="Test finding",
            explanation="Explanation",
            recommendation="Recommendation",
            confidence=0.75,
            evidence_ids=(uuid4(), uuid4()),
        ),
    )
    repository = FakeAssessmentRepository()
    repository.saved_findings = list(findings)
    service = AssessmentService(repository)
    path = tmp_path / "assessment.csv"

    count = service.export_csv(path)

    assert count == 1
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["rule_id"] == "test_rule"
    assert rows[0]["severity"] == "medium"
    assert ";" in rows[0]["evidence_ids"]


def test_assessment_exports_versioned_json(tmp_path: Path) -> None:
    findings = (
        AssessmentFinding(
            finding_id=uuid4(),
            rule_id="test_rule",
            severity=Severity.HIGH,
            title="Test finding",
            explanation="Explanation",
            recommendation="Recommendation",
            confidence=0.8,
            evidence_ids=(uuid4(),),
        ),
    )
    repository = FakeAssessmentRepository()
    repository.saved_findings = list(findings)
    service = AssessmentService(repository)
    path = tmp_path / "assessment.json"

    count = service.export_json(path)

    assert count == 1
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["findings"][0]["rule_id"] == "test_rule"
    assert payload["findings"][0]["severity"] == "high"
    assert payload["generated_at"]


def test_assessment_search_normalizes_and_filters() -> None:
    asset1 = _asset("192.168.1.10", "lab-host")
    asset2 = _asset("10.0.0.5", "prod-server")
    repository = FakeAssessmentRepository(assets=(asset1, asset2))
    service = AssessmentService(repository)

    service.assess(search="  LAB-HOST  ")

    assert repository.searches == ["LAB-HOST"]