"""Assessment snapshot reporting orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from uuid import UUID

from netsentinel.domain.models import (
    AssessmentFinding,
    DeviceAsset,
    PortObservation,
)


class ReportingRepository(Protocol):
    """Persistence operations needed for reporting."""

    def list_assets(self, search: str | None = None) -> tuple[DeviceAsset, ...]:
        """Return inventory records."""

    def list_port_observations(
        self, job_id: UUID | None = None
    ) -> tuple[PortObservation, ...]:
        """Return normalized port observations."""

    def list_findings(
        self, job_id: UUID | None = None
    ) -> tuple[AssessmentFinding, ...]:
        """Return evidence-linked findings."""


class ReportService:
    """Generate assessment snapshot reports in multiple formats."""

    def __init__(self, repository: ReportingRepository) -> None:
        self._repository = repository

    def generate_snapshot(
        self,
        *,
        job_id: UUID | None = None,
        search: str | None = None,
        operator: str = "system",
    ) -> AssessmentSnapshot:
        """Build an immutable assessment snapshot."""
        assets = self._repository.list_assets(search)
        observations = self._repository.list_port_observations(job_id)
        findings = self._repository.list_findings(job_id)

        return AssessmentSnapshot(
            snapshot_id=UUID(int=0),  # placeholder, will be replaced
            generated_at=datetime.now(UTC),
            operator=operator,
            job_id=job_id,
            search_filter=search,
            assets=assets,
            observations=observations,
            findings=findings,
        )

    def export_json(self, snapshot: AssessmentSnapshot, path: Path) -> int:
        """Export snapshot to a versioned JSON file."""
        import json

        payload = {
            "schema_version": 1,
            "generated_at": snapshot.generated_at.isoformat(),
            "operator": snapshot.operator,
            "job_id": str(snapshot.job_id) if snapshot.job_id else None,
            "search_filter": snapshot.search_filter,
            "assets": [
                {
                    "asset_id": str(a.asset_id),
                    "ip_address": str(a.address),
                    "mac_address": a.mac_address,
                    "hostname": a.hostname,
                    "vendor": a.vendor,
                    "response_time_ms": a.response_time_ms,
                    "first_seen": a.first_seen.isoformat(),
                    "last_seen": a.last_seen.isoformat(),
                    "status": a.status,
                }
                for a in snapshot.assets
            ],
            "port_observations": [
                {
                    "observation_id": str(o.observation_id),
                    "address": str(o.address),
                    "port": o.port,
                    "protocol": o.protocol,
                    "state": o.state,
                    "service": o.service,
                    "version": o.version,
                    "source": o.source.value,
                    "observed_at": o.observed_at.isoformat(),
                }
                for o in snapshot.observations
            ],
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
                for f in snapshot.findings
            ],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return len(snapshot.findings)

    def export_csv(self, snapshot: AssessmentSnapshot, path: Path) -> int:
        """Export snapshot findings to a CSV file."""
        import csv

        if not snapshot.findings:
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
            for finding in snapshot.findings:
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
        return len(snapshot.findings)

    def export_pdf(self, snapshot: AssessmentSnapshot, path: Path) -> int:
        """Export snapshot to a PDF report using reportlab."""
        try:
            from reportlab.lib import colors  # type: ignore[import-untyped]
            from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
            from reportlab.lib.styles import getSampleStyleSheet  # type: ignore[import-untyped]
            from reportlab.lib.units import cm  # type: ignore[import-untyped]
            from reportlab.platypus import (  # type: ignore[import-untyped]
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError as exc:
            raise RuntimeError(
                "PDF export requires 'reportlab' package. "
                "Install with: pip install reportlab"
            ) from exc

        doc = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        elements = []

        # Title
        elements.append(Paragraph("NetSentinel Assessment Report", styles["Title"]))
        elements.append(Spacer(1, 0.5 * cm))

        # Metadata
        meta_data = [
            ["Generated", snapshot.generated_at.isoformat()],
            ["Operator", snapshot.operator],
            ["Job ID", str(snapshot.job_id) if snapshot.job_id else "N/A"],
            ["Scope filter", snapshot.search_filter or "All assets"],
            ["Assets found", str(len(snapshot.assets))],
            ["Port observations", str(len(snapshot.observations))],
            ["Findings", str(len(snapshot.findings))],
        ]
        meta_table = Table(meta_data, colWidths=[4 * cm, 12 * cm])
        meta_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ]
            )
        )
        elements.append(meta_table)
        elements.append(Spacer(1, 1 * cm))

        # Findings table
        if snapshot.findings:
            elements.append(Paragraph("Findings", styles["Heading2"]))
            elements.append(Spacer(1, 0.3 * cm))

            finding_data = [
                ["Severity", "Rule", "Title", "Confidence", "Evidence"]
            ]
            severity_colors = {
                "low": colors.lightblue,
                "medium": colors.lightyellow,
                "high": colors.lightcoral,
                "critical": colors.red,
            }
            for finding in snapshot.findings:
                finding_data.append(
                    [
                        finding.severity.value.upper(),
                        finding.rule_id,
                        finding.title[:60] + ("..." if len(finding.title) > 60 else ""),
                        f"{finding.confidence:.2f}",
                        str(len(finding.evidence_ids)),
                    ]
                )

            finding_table = Table(
                finding_data,
                colWidths=[2 * cm, 2.5 * cm, 7 * cm, 2 * cm, 2 * cm],
                repeatRows=1,
            )
            style_cmds = [
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
            for i, finding in enumerate(snapshot.findings, start=1):
                bg_color = severity_colors.get(finding.severity.value, colors.white)
                style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg_color))

            finding_table.setStyle(TableStyle(style_cmds))
            elements.append(finding_table)
        else:
            elements.append(Paragraph("No findings generated.", styles["Normal"]))

        doc.build(elements)
        return len(snapshot.findings)


class AssessmentSnapshot:
    """Immutable snapshot of an assessment run."""

    def __init__(
        self,
        snapshot_id: UUID,
        generated_at: datetime,
        operator: str,
        job_id: UUID | None,
        search_filter: str | None,
        assets: tuple[DeviceAsset, ...],
        observations: tuple[PortObservation, ...],
        findings: tuple[AssessmentFinding, ...],
    ) -> None:
        self.snapshot_id = snapshot_id
        self.generated_at = generated_at
        self.operator = operator
        self.job_id = job_id
        self.search_filter = search_filter
        self.assets = assets
        self.observations = observations
        self.findings = findings