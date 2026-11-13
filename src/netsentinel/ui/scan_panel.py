"""Reusable validated input panel for authorized network operations."""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from netsentinel.domain.enums import OperationType


@dataclass(frozen=True, slots=True)
class ScanFormData:
    """Raw form values passed to the application-layer operation coordinator."""

    targets: str
    exclusions: str
    ports: str
    interface: str
    operator: str
    reason: str
    confirmed: bool


class ScanPanel(QWidget):
    """Form and status controls shared by discovery and port scanning."""

    start_requested = Signal(object)
    cancel_requested = Signal()

    def __init__(self, operation: OperationType, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.operation = operation
        self._build_ui()

    def _build_ui(self) -> None:
        title = (
            "Network Discovery"
            if self.operation is OperationType.DISCOVERY
            else "TCP Port Scanner"
        )
        description = (
            "Discover authorized local IPv4 hosts through ARP. Npcap and suitable "
            "Windows permissions may be required."
            if self.operation is OperationType.DISCOVERY
            else "Check authorized IPv4 targets with bounded TCP Connect probes."
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(42, 42, 42, 42)
        layout.setSpacing(16)

        heading = QLabel(title)
        heading.setObjectName("pageHeading")
        description_label = QLabel(description)
        description_label.setObjectName("status")
        description_label.setWordWrap(True)
        description_label.setMaximumWidth(760)
        layout.addWidget(heading)
        layout.addWidget(description_label)

        form = QFormLayout()
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(12)
        self.targets = QLineEdit()
        self.targets.setPlaceholderText("192.168.1.0/24 or 192.168.1.10,192.168.1.11")
        form.addRow("Targets", self.targets)

        self.exclusions = QLineEdit()
        self.exclusions.setPlaceholderText("Optional exclusions, comma-separated")
        form.addRow("Exclusions", self.exclusions)

        self.ports = QLineEdit()
        self.ports.setPlaceholderText("22,80,443 or 1-1024")
        if self.operation is OperationType.PORT_SCAN:
            form.addRow("TCP ports", self.ports)

        self.interface = QLineEdit()
        self.interface.setPlaceholderText("Optional interface name, e.g. Ethernet")
        if self.operation is OperationType.DISCOVERY:
            form.addRow("Interface", self.interface)

        self.operator = QLineEdit()
        self.operator.setPlaceholderText("Operator identity")
        form.addRow("Operator", self.operator)

        self.reason = QLineEdit()
        self.reason.setPlaceholderText("Reason and authorization context")
        form.addRow("Reason", self.reason)
        layout.addLayout(form)

        self.confirmation = QCheckBox(
            "I confirm that I am authorized to assess these targets."
        )
        self.confirmation.setObjectName("authorizationCheck")
        layout.addWidget(self.confirmation)

        actions = QHBoxLayout()
        self.start_button = QPushButton(
            "Start discovery"
            if self.operation is OperationType.DISCOVERY
            else "Start TCP scan"
        )
        self.start_button.setObjectName("primaryButton")
        self.start_button.clicked.connect(self._emit_start)
        self.cancel_button = QPushButton("Cancel operation")
        self.cancel_button.setObjectName("secondaryButton")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_requested.emit)
        actions.addWidget(self.start_button)
        actions.addWidget(self.cancel_button)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        layout.addWidget(self.progress)

        self.status = QLabel("Ready. No operation has been started.")
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        layout.addStretch(1)

    def form_data(self) -> ScanFormData:
        """Return a snapshot of the current user-entered values."""
        return ScanFormData(
            targets=self.targets.text(),
            exclusions=self.exclusions.text(),
            ports=self.ports.text(),
            interface=self.interface.text(),
            operator=self.operator.text(),
            reason=self.reason.text(),
            confirmed=self.confirmation.isChecked(),
        )

    def set_running(self, running: bool) -> None:
        """Toggle controls while a background operation is active."""
        self.start_button.setEnabled(not running)
        self.cancel_button.setEnabled(running)
        self.targets.setEnabled(not running)
        self.exclusions.setEnabled(not running)
        self.ports.setEnabled(not running)
        self.interface.setEnabled(not running)
        self.operator.setEnabled(not running)
        self.reason.setEnabled(not running)
        self.confirmation.setEnabled(not running)

    def set_progress(self, completed: int, total: int, message: str) -> None:
        """Update progress safely for an event received from a worker."""
        if total > 0:
            self.progress.setRange(0, total)
            self.progress.setValue(min(completed, total))
        self.status.setText(message)

    def set_status(self, message: str) -> None:
        """Set a user-facing operation status."""
        self.status.setText(message)

    def _emit_start(self) -> None:
        self.start_requested.emit(self.form_data())
