"""Qt view for evidence-based security assessment."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netsentinel.domain.enums import Severity
from netsentinel.domain.models import AssessmentFinding


class AssessmentPanel(QWidget):
    """Display assessment findings with severity coloring and evidence links."""

    assess_requested = Signal()
    export_csv_requested = Signal()
    export_json_requested = Signal()

    _HEADERS = (
        "Severity",
        "Rule",
        "Title",
        "Explanation",
        "Recommendation",
        "Confidence",
        "Evidence count",
    )

    _SEVERITY_COLORS = {
        Severity.LOW: "#60a5fa",
        Severity.MEDIUM: "#fbbf24",
        Severity.HIGH: "#f87171",
        Severity.CRITICAL: "#ef4444",
    }

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(42, 42, 42, 42)
        layout.setSpacing(16)

        heading = QLabel("Security Assessment")
        heading.setObjectName("pageHeading")
        description = QLabel(
            "Deterministic findings derived from persisted port observations and "
            "service fingerprints. Each finding cites its evidence by observation ID."
        )
        description.setObjectName("status")
        description.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(description)

        controls = QHBoxLayout()
        self.assess_button = QPushButton("Run Assessment")
        self.assess_button.clicked.connect(self.assess_requested.emit)
        self.export_csv_button = QPushButton("Export CSV")
        self.export_csv_button.clicked.connect(self.export_csv_requested.emit)
        self.export_json_button = QPushButton("Export JSON")
        self.export_json_button.clicked.connect(self.export_json_requested.emit)
        controls.addWidget(self.assess_button)
        controls.addStretch(1)
        controls.addWidget(self.export_csv_button)
        controls.addWidget(self.export_json_button)
        layout.addLayout(controls)

        self.table = QTableWidget(0, len(self._HEADERS))
        self.table.setHorizontalHeaderLabels(self._HEADERS)
        self.table.setObjectName("assessmentTable")
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, stretch=1)

        self.status = QLabel("No assessment run yet.")
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

    def set_findings(self, findings: tuple[AssessmentFinding, ...]) -> None:
        """Render findings returned by the assessment service."""
        self.table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            severity = finding.severity
            color = self._SEVERITY_COLORS.get(severity, "#e0f2fe")
            severity_item = QTableWidgetItem(severity.value)
            severity_item.setBackground(QBrush(QColor(color)))
            self.table.setItem(row, 0, severity_item)

            self.table.setItem(row, 1, QTableWidgetItem(finding.rule_id))
            self.table.setItem(row, 2, QTableWidgetItem(finding.title))
            self.table.setItem(row, 3, QTableWidgetItem(finding.explanation))
            self.table.setItem(row, 4, QTableWidgetItem(finding.recommendation))
            self.table.setItem(row, 5, QTableWidgetItem(f"{finding.confidence:.2f}"))
            self.table.setItem(row, 6, QTableWidgetItem(str(len(finding.evidence_ids))))

        self.status.setText(f"{len(findings)} finding(s) loaded.")

    def set_status(self, message: str) -> None:
        """Set an actionable assessment status or error."""
        self.status.setText(message)