"""Evidence-based security assessment orchestration."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

from netsentinel.domain.enums import Severity
from netsentinel.domain.models import (
    AssessmentFinding,
    DeviceAsset,
    PortObservation,
)


class AssessmentRepository(Protocol):
    """Persistence operations needed by the assessment use case."""

    def list_assets(self, search: str | None = None) -> tuple[DeviceAsset, ...]:
        """Return inventory records."""

    def list_port_observations(
        self, job_id: UUID | None = None
    ) -> tuple[PortObservation, ...]:
        """Return normalized port observations."""

    def save_finding(
        self, finding: AssessmentFinding, job_id: UUID | None = None
    ) -> None:
        """Persist an evidence-linked assessment finding."""

    def list_findings(
        self, job_id: UUID | None = None
    ) -> tuple[AssessmentFinding, ...]:
        """Return evidence-linked findings."""


class AssessmentService:
    """Evaluate assets and port observations into deterministic findings."""

    def __init__(self, repository: AssessmentRepository) -> None:
        self._repository = repository

    def assess(
        self,
        *,
        job_id: UUID | None = None,
        search: str | None = None,
    ) -> tuple[AssessmentFinding, ...]:
        """Run deterministic rules against current evidence and persist findings."""
        normalized_search = search.strip() if search else None
        assets = self._repository.list_assets(normalized_search)
        observations = self._repository.list_port_observations(job_id)

        findings: list[AssessmentFinding] = []
        findings.extend(_rule_open_ports_without_service(assets, observations))
        findings.extend(_rule_insecure_services_detected(assets, observations))
        findings.extend(_rule_outdated_service_versions(assets, observations))
        findings.extend(_rule_unusual_high_ports(assets, observations))
        findings.extend(_rule_multiple_open_ports(assets, observations))

        for finding in findings:
            self._repository.save_finding(finding, job_id)

        return tuple(findings)

    def list_findings(
        self, job_id: UUID | None = None
    ) -> tuple[AssessmentFinding, ...]:
        """Return previously computed findings."""
        return self._repository.list_findings(job_id)

    def export_csv(self, path: Path) -> int:
        """Export all findings to a CSV file."""
        findings = self._repository.list_findings()
        if not findings:
            path.write_text("", encoding="utf-8")
            return 0
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "finding_id",
                    "rule_id",
                    "severity",
                    "title",
                    "explanation",
                    "recommendation",
                    "confidence",
                    "evidence_ids",
                ]
            )
            for finding in findings:
                writer.writerow(
                    [
                        str(finding.finding_id),
                        finding.rule_id,
                        finding.severity.value,
                        finding.title,
                        finding.explanation,
                        finding.recommendation,
                        f"{finding.confidence:.2f}",
                        ";".join(str(eid) for eid in finding.evidence_ids),
                    ]
                )
        return len(findings)

    def export_json(self, path: Path) -> int:
        """Export all findings to a versioned JSON file."""
        findings = self._repository.list_findings()
        payload = {
            "schema_version": 1,
            "generated_at": datetime.now(UTC).isoformat(),
            "findings": [
                {
                    "finding_id": str(f.finding_id),
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "explanation": f.explanation,
                    "recommendation": f.recommendation,
                    "confidence": f.confidence,
                    "evidence_ids": [str(eid) for eid in f.evidence_ids],
                }
                for f in findings
            ],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return len(findings)


# --- Deterministic assessment rules ---

# Well-known ports commonly associated with insecure or legacy services
_INSECURE_SERVICE_PORTS = {
    21: ("ftp", "Unencrypted file transfer; credentials sent in cleartext"),
    23: ("telnet", "Unencrypted remote shell; credentials sent in cleartext"),
    53: ("dns", "Open DNS resolver may be abused for amplification"),
    69: ("tftp", "Trivial FTP without authentication"),
    79: ("finger", "Information disclosure service"),
    110: ("pop3", "Unencrypted mail retrieval"),
    111: ("rpcbind", "RPC endpoint mapper; historically exploitable"),
    135: ("msrpc", "Microsoft RPC; large attack surface"),
    139: ("netbios-ssn", "NetBIOS session; legacy SMB"),
    143: ("imap", "Unencrypted mail access"),
    161: ("snmp", "SNMP v1/v2c uses community strings as weak auth"),
    445: ("microsoft-ds", "SMB; ensure signing and disable SMBv1"),
    513: ("rlogin", "Unencrypted remote login"),
    514: ("rsh", "Unencrypted remote shell"),
    1433: ("ms-sql-s", "MS SQL Server; ensure strong auth and patching"),
    1521: ("oracle", "Oracle TNS; default accounts and padding attacks"),
    3306: ("mysql", "MySQL; ensure strong auth and disable remote root"),
    3389: ("ms-wbt-server", "RDP; ensure NLA and patching"),
    5432: ("postgresql", "PostgreSQL; ensure strong auth"),
    5900: ("vnc", "VNC; often weak or no authentication"),
    6379: ("redis", "Redis; ensure binding and auth"),
    8080: ("http-proxy", "Common alternate HTTP; check for exposed admin panels"),
    27017: ("mongodb", "MongoDB; ensure auth and binding"),
}


def _rule_open_ports_without_service(
    assets: tuple[DeviceAsset, ...],
    observations: tuple[PortObservation, ...],
) -> tuple[AssessmentFinding, ...]:
    """Flag open ports where no service/version info was collected."""
    findings: list[AssessmentFinding] = []
    open_by_addr: dict[IPv4Address, list[PortObservation]] = {}
    for obs in observations:
        if obs.state == "open":
            open_by_addr.setdefault(obs.address, []).append(obs)

    for address, obs_list in open_by_addr.items():
        unknown = [o for o in obs_list if not o.service and not o.version]
        if not unknown:
            continue
        evidence = tuple(o.observation_id for o in unknown)
        findings.append(
            AssessmentFinding(
                finding_id=uuid4(),
                rule_id="open_port_no_service_info",
                severity=Severity.LOW,
                title=(
                    f"{len(unknown)} open port(s) without service identification "
                    f"on {address}"
                ),
                explanation=(
                    "Open ports were detected but no service name or version was "
                    "reported. This may indicate a custom service, a service that "
                    "did not respond to probes, or a bannerless listener."
                ),
                recommendation=(
                    "Verify these services manually. Enable Nmap service detection "
                    "(-sV) for deeper fingerprinting in a subsequent authorized scan."
                ),
                confidence=0.7,
                evidence_ids=evidence,
            )
        )
    return tuple(findings)


def _rule_insecure_services_detected(
    assets: tuple[DeviceAsset, ...],
    observations: tuple[PortObservation, ...],
) -> tuple[AssessmentFinding, ...]:
    """Flag open ports matching well-known insecure service definitions."""
    findings: list[AssessmentFinding] = []
    for obs in observations:
        if obs.state != "open":
            continue
        info = _INSECURE_SERVICE_PORTS.get(obs.port)
        if not info:
            continue
        service_name, rationale = info
        detected_service = (obs.service or "").lower()
        matches = detected_service == service_name or service_name in detected_service
        if not matches and obs.service:
            continue
        severity = Severity.MEDIUM
        if obs.port in {21, 23, 69, 110, 143, 513, 514}:
            severity = Severity.HIGH
        findings.append(
            AssessmentFinding(
                finding_id=uuid4(),
                rule_id="insecure_service_exposed",
                severity=severity,
                title=(
                    f"Insecure service {service_name.upper()} ({obs.port}/tcp) "
                    f"exposed on {obs.address}"
                ),
                explanation=(
                    f"An open port {obs.port}/tcp matches {service_name.upper()}. "
                    f"{rationale}. Detected service: {obs.service or 'unknown'}."
                ),
                recommendation=(
                    "Disable or replace with a secure alternative (e.g., SFTP "
                    "instead of FTP, SSH instead of Telnet/RSH/Rlogin). If the "
                    "service is required, restrict access via firewall, enforce "
                    "strong authentication, and monitor for abuse."
                ),
                confidence=0.85 if matches else 0.65,
                evidence_ids=(obs.observation_id,),
            )
        )
    return tuple(findings)


def _rule_outdated_service_versions(
    assets: tuple[DeviceAsset, ...],
    observations: tuple[PortObservation, ...],
) -> tuple[AssessmentFinding, ...]:
    """Flag services with version strings suggesting outdated releases."""
    findings: list[AssessmentFinding] = []
    # Heuristic patterns indicating likely outdated versions
    outdated_patterns = [
        ("apache", ["2.2.", "2.0.", "1.3."]),
        ("nginx", ["1.4.", "1.6.", "1.8.", "1.10.", "1.12.", "1.14."]),
        ("openssh", ["7.2", "7.3", "7.4", "7.5", "7.6", "7.7", "7.8", "7.9"]),
        ("mysql", ["5.5.", "5.6.", "5.7.0", "5.7.1", "5.7.2", "5.7.3", "5.7.4"]),
        ("postgresql", ["9.1", "9.2", "9.3", "9.4", "9.5", "9.6", "10.", "11.", "12."]),
        ("redis", ["4.0", "5.0", "6.0", "6.1", "6.2.0", "6.2.1", "6.2.2", "6.2.3"]),
        ("mongodb", ["3.2", "3.4", "3.6", "4.0", "4.2", "4.4"]),
    ]
    for obs in observations:
        if obs.state != "open" or not obs.version:
            continue
        combined = f"{obs.service or ''} {obs.version}".lower()
        for product, old_versions in outdated_patterns:
            if product not in combined:
                continue
            for old in old_versions:
                if old in combined:
                    findings.append(
                        AssessmentFinding(
                            finding_id=uuid4(),
                            rule_id="outdated_service_version",
                            severity=Severity.MEDIUM,
                            title=(
                                f"Potentially outdated {product} version on "
                                f"{obs.address}:{obs.port}"
                            ),
                            explanation=(
                                f"Service version '{obs.version}' matches a pattern "
                                f"associated with older {product} releases. This is a "
                                f"heuristic indicator, not a confirmed vulnerability."
                            ),
                            recommendation=(
                                "Verify the exact version with the vendor. "
                                "Apply security patches or upgrade to a "
                                "supported release. Cross-reference with vendor "
                                "advisories for confirmed vulnerabilities."
                            ),
                            confidence=0.55,
                            evidence_ids=(obs.observation_id,),
                        )
                    )
                    break
    return tuple(findings)


def _rule_unusual_high_ports(
    assets: tuple[DeviceAsset, ...],
    observations: tuple[PortObservation, ...],
) -> tuple[AssessmentFinding, ...]:
    """Flag open ports in the ephemeral/high range without known service."""
    findings: list[AssessmentFinding] = []
    for obs in observations:
        if obs.state != "open":
            continue
        if obs.port < 49152:
            continue
        if obs.service or obs.version:
            continue
        findings.append(
            AssessmentFinding(
                finding_id=uuid4(),
                rule_id="unusual_high_port_open",
                severity=Severity.LOW,
                title=(
                    f"Open ephemeral-range port {obs.port}/tcp on {obs.address} "
                    f"without service info"
                ),
                explanation=(
                    f"Port {obs.port} is in the dynamic/ephemeral range "
                    f"(49152-65535) and is open without a detectable service. "
                    f"This may indicate a temporary service, a custom application, "
                    f"or potential unauthorized software."
                ),
                recommendation=(
                    "Investigate the process listening on this port. Determine if "
                    "it is authorized and expected. Block at the firewall if "
                    "unnecessary."
                ),
                confidence=0.5,
                evidence_ids=(obs.observation_id,),
            )
        )
    return tuple(findings)


def _rule_multiple_open_ports(
    assets: tuple[DeviceAsset, ...],
    observations: tuple[PortObservation, ...],
) -> tuple[AssessmentFinding, ...]:
    """Flag assets with many open ports as increased attack surface."""
    findings: list[AssessmentFinding] = []
    open_by_addr: dict[IPv4Address, list[PortObservation]] = {}
    for obs in observations:
        if obs.state == "open":
            open_by_addr.setdefault(obs.address, []).append(obs)

    for address, obs_list in open_by_addr.items():
        if len(obs_list) >= 10:
            evidence = tuple(o.observation_id for o in obs_list)
            findings.append(
                AssessmentFinding(
                    finding_id=uuid4(),
                    rule_id="high_open_port_count",
                    severity=Severity.LOW,
                    title=f"High number of open ports ({len(obs_list)}) on {address}",
                    explanation=(
                        f"This host has {len(obs_list)} open TCP ports. A large "
                        f"attack surface increases the likelihood of vulnerable "
                        f"services and complicates monitoring."
                    ),
                    recommendation=(
                        "Review each open port. Close or firewall any that are "
                        "not strictly required. Implement network segmentation and "
                        "host-based firewall rules."
                    ),
                    confidence=0.6,
                    evidence_ids=evidence,
                )
            )
    return tuple(findings)


def _normalize_text(value: str | None) -> str:
    if value is None:
        return ""
    return value.strip().lower()