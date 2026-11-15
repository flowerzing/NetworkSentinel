"""Qt view for the dashboard summary."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from netsentinel.domain.models import AssessmentFinding


class DashboardPanel(QWidget):
    """Summary dashboard showing key metrics from inventory and assessment."""

    refresh_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(42, 42, 42, 42)
        layout.setSpacing(16)

        heading = QLabel("Dashboard")
        heading.setObjectName("pageHeading")
        description = QLabel(
            "Overview of discovered devices, open ports, and security findings "
            "from authorized operations."
        )
        description.setObjectName("status")
        description.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(description)

        # Metrics grid
        metrics_layout = QGridLayout()
        metrics_layout.setSpacing(16)

        self._devices_card = self._create_metric_card(
            "Devices", "0", "Total discovered devices"
        )
        self._ports_card = self._create_metric_card(
            "Open Ports", "0", "Total open ports across all devices"
        )
        self._findings_card = self._create_metric_card(
            "Findings", "0", "Security assessment findings"
        )
        self._critical_card = self._create_metric_card(
            "Critical", "0", "Critical severity findings"
        )

        metrics_layout.addWidget(self._devices_card, 0, 0)
        metrics_layout.addWidget(self._ports_card, 0, 1)
        metrics_layout.addWidget(self._findings_card, 1, 0)
        metrics_layout.addWidget(self._critical_card, 1, 1)

        layout.addLayout(metrics_layout)

        # Quick actions
        actions_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh Dashboard")
        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        actions_layout.addWidget(self.refresh_button)
        actions_layout.addStretch(1)
        layout.addLayout(actions_layout)

        # Status
        self.status = QLabel("No data loaded. Run discovery and assessment.")
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        layout.addStretch(1)

    def _create_metric_card(
        self, title: str, value: str, description: str
    ) -> QWidget:
        """Create a metric card widget."""
        card = QWidget()
        card.setObjectName("metricCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 20, 24, 20)
        card_layout.setSpacing(8)

        title_label = QLabel(title)
        title_label.setObjectName("metricTitle")
        card_layout.addWidget(title_label)

        value_label = QLabel(value)
        value_label.setObjectName("metricValue")
        card_layout.addWidget(value_label)

        desc_label = QLabel(description)
        desc_label.setObjectName("metricDescription")
        card_layout.addWidget(desc_label)

        # Store references for later updates
        card.value_label = value_label  # type: ignore[attr-defined]

        return card

    def update_metrics(
        self,
        device_count: int,
        open_port_count: int,
        findings: tuple[AssessmentFinding, ...],
    ) -> None:
        """Update dashboard metrics."""
        self._devices_card.value_label.setText(str(device_count))  # type: ignore[attr-defined]
        self._ports_card.value_label.setText(str(open_port_count))  # type: ignore[attr-defined]
        self._findings_card.value_label.setText(str(len(findings)))  # type: ignore[attr-defined]
        critical_count = sum(1 for f in findings if f.severity.value == "critical")
        self._critical_card.value_label.setText(str(critical_count))  # type: ignore[attr-defined]
        self.status.setText("Dashboard updated from latest data.")

    def set_status(self, message: str) -> None:
        """Set status message."""
        self.status.setText(message)