"""Qt view for assessment report generation."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class ReportsPanel(QWidget):
    """Generate and export assessment reports in multiple formats."""

    generate_requested = Signal()
    export_json_requested = Signal()
    export_csv_requested = Signal()
    export_pdf_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(42, 42, 42, 42)
        layout.setSpacing(16)

        heading = QLabel("Reports")
        heading.setObjectName("pageHeading")
        description = QLabel(
            "Generate assessment snapshots and export them as JSON, CSV, or PDF. "
            "Snapshots include assets, port observations, and deterministic findings."
        )
        description.setObjectName("status")
        description.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(description)

        # Generation controls
        gen_layout = QHBoxLayout()
        self.generate_button = QPushButton("Generate Snapshot")
        self.generate_button.clicked.connect(self.generate_requested.emit)
        gen_layout.addWidget(self.generate_button)
        gen_layout.addStretch(1)
        layout.addLayout(gen_layout)

        # Export controls
        export_layout = QHBoxLayout()
        self.export_json_button = QPushButton("Export JSON")
        self.export_json_button.clicked.connect(self.export_json_requested.emit)
        self.export_json_button.setEnabled(False)

        self.export_csv_button = QPushButton("Export CSV")
        self.export_csv_button.clicked.connect(self.export_csv_requested.emit)
        self.export_csv_button.setEnabled(False)

        self.export_pdf_button = QPushButton("Export PDF")
        self.export_pdf_button.clicked.connect(self.export_pdf_requested.emit)
        self.export_pdf_button.setEnabled(False)

        export_layout.addWidget(self.export_json_button)
        export_layout.addWidget(self.export_csv_button)
        export_layout.addWidget(self.export_pdf_button)
        export_layout.addStretch(1)
        layout.addLayout(export_layout)

        # Status
        self.status = QLabel("No snapshot generated.")
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        layout.addStretch(1)

    def set_generated(self, message: str) -> None:
        """Enable export buttons after successful snapshot generation."""
        self.status.setText(message)
        self.export_json_button.setEnabled(True)
        self.export_csv_button.setEnabled(True)
        self.export_pdf_button.setEnabled(True)

    def set_status(self, message: str) -> None:
        """Set an actionable reports status or error."""
        self.status.setText(message)