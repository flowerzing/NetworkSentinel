"""Qt view for the persisted device inventory."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netsentinel.domain.models import DeviceAsset


class InventoryPanel(QWidget):
    """Display persisted assets with search and export controls."""

    refresh_requested = Signal(str)
    export_csv_requested = Signal(str)
    export_json_requested = Signal(str)

    _HEADERS = (
        "IP address",
        "MAC address",
        "Hostname",
        "Vendor",
        "Response",
        "Status",
        "First seen",
        "Last seen",
    )

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(42, 42, 42, 42)
        layout.setSpacing(16)

        heading = QLabel("Device Inventory")
        heading.setObjectName("pageHeading")
        description = QLabel(
            "Persistent records from authorized discovery operations. Search and "
            "exports use the current SQLite inventory only."
        )
        description.setObjectName("status")
        description.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(description)

        controls = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search IP address, hostname, or MAC")
        self.search.returnPressed.connect(self._emit_refresh)
        controls.addWidget(self.search, stretch=1)

        self.search_button = QPushButton("Apply filter")
        self.search_button.clicked.connect(self._emit_refresh)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._emit_refresh)
        self.export_csv_button = QPushButton("Export CSV")
        self.export_csv_button.clicked.connect(
            lambda: self.export_csv_requested.emit(self.search.text().strip())
        )
        self.export_json_button = QPushButton("Export JSON")
        self.export_json_button.clicked.connect(
            lambda: self.export_json_requested.emit(self.search.text().strip())
        )
        controls.addWidget(self.search_button)
        controls.addWidget(self.refresh_button)
        controls.addWidget(self.export_csv_button)
        controls.addWidget(self.export_json_button)
        layout.addLayout(controls)

        self.table = QTableWidget(0, len(self._HEADERS))
        self.table.setHorizontalHeaderLabels(self._HEADERS)
        self.table.setObjectName("inventoryTable")
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, stretch=1)

        self.status = QLabel("No inventory loaded.")
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

    def set_assets(self, assets: tuple[DeviceAsset, ...], search: str) -> None:
        """Render assets returned by the application service."""
        self.table.setRowCount(len(assets))
        for row, asset in enumerate(assets):
            values = (
                str(asset.address),
                asset.mac_address or "—",
                asset.hostname or "—",
                asset.vendor or "—",
                _format_response(asset.response_time_ms),
                asset.status,
                _format_datetime(asset.first_seen),
                _format_datetime(asset.last_seen),
            )
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(value))
        suffix = f" matching {search!r}" if search else ""
        self.status.setText(f"{len(assets)} device(s) loaded{suffix}.")

    def set_status(self, message: str) -> None:
        """Set an actionable inventory status or error."""
        self.status.setText(message)

    def _emit_refresh(self) -> None:
        self.refresh_requested.emit(self.search.text().strip())


def _format_response(response_time_ms: float | None) -> str:
    return f"{response_time_ms:.1f} ms" if response_time_ms is not None else "—"


def _format_datetime(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")
