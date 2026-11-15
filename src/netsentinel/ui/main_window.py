"""Main Qt window and coordination for authorized active operations."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from netsentinel.application.assessment import AssessmentService
from netsentinel.application.authorization import AuthorizationService
from netsentinel.application.discovery import DiscoveryService
from netsentinel.application.events import JobErrorEvent, ProgressEvent
from netsentinel.application.inventory import InventoryService
from netsentinel.application.monitoring import NetworkMonitorService
from netsentinel.application.policies import SafetyLimits, SafetyPolicy
from netsentinel.application.port_scanning import PortScanService
from netsentinel.domain.enums import OperationType
from netsentinel.domain.errors import NetSentinelError
from netsentinel.domain.models import AuthorizationRecord, ScanScope
from netsentinel.domain.validation import parse_ports, parse_scope
from netsentinel.infrastructure.config import AppConfig
from netsentinel.infrastructure.database.connection import SQLiteDatabase
from netsentinel.infrastructure.database.repositories import SQLiteRepository
from netsentinel.infrastructure.monitoring.psutil_monitor import PsutilMonitorProvider
from netsentinel.infrastructure.scanning.scapy_discovery import ScapyDiscoveryAdapter
from netsentinel.infrastructure.scanning.tcp_scanner import TcpConnectScanner
from netsentinel.ui.assessment_panel import AssessmentPanel
from netsentinel.ui.inventory_panel import InventoryPanel
from netsentinel.ui.monitor_panel import MonitorPanel
from netsentinel.ui.scan_panel import ScanFormData, ScanPanel
from netsentinel.ui.workers import Worker, WorkerManager

_NAVIGATION = (
    "Dashboard",
    "Network Discovery",
    "Port Scanner",
    "Network Monitor",
    "Device Inventory",
    "Security Assessment",
    "Reports",
    "Settings",
    "About",
)


class MainWindow(QMainWindow):
    """Desktop shell coordinating validated services and background workers."""

    def __init__(self, config: AppConfig) -> None:
        super().__init__()
        self._config = config
        self._database = SQLiteDatabase(config.database_path)
        self._repository = SQLiteRepository(self._database)
        self._policy = SafetyPolicy(
            limits=SafetyLimits(
                max_scope_hosts=config.max_scope_hosts,
                max_ports=config.max_ports,
                max_concurrency=config.max_concurrency,
                max_rate_per_second=config.max_rate_per_second,
                connect_timeout_seconds=config.connect_timeout_seconds,
            )
        )
        self._authorization = AuthorizationService(self._policy)
        self._worker_manager = WorkerManager()
        self._active_panels: dict[UUID, ScanPanel] = {}
        self._discovery_service = DiscoveryService(
            self._policy,
            ScapyDiscoveryAdapter(max_hosts=config.max_scope_hosts),
            self._repository,
        )
        self._port_scan_service = PortScanService(
            self._policy,
            TcpConnectScanner(),
            self._repository,
        )
        self._monitor_service = NetworkMonitorService(PsutilMonitorProvider())
        self._inventory_service = InventoryService(self._repository)
        self._assessment_service = AssessmentService(self._repository)
        self._monitor_timer = QTimer(self)
        self._monitor_timer.timeout.connect(self._refresh_monitor)
        self.setWindowTitle("NetSentinel")
        self.resize(1120, 720)
        self.setMinimumSize(920, 600)
        self._load_stylesheet()
        self._build_ui()

    def _build_ui(self) -> None:
        root = QWidget(self)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(240)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 24, 20, 20)
        sidebar_layout.setSpacing(12)

        brand = QLabel("NETSENTINEL")
        brand.setObjectName("brand")
        subtitle = QLabel("Defensive network visibility")
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        sidebar_layout.addWidget(brand)
        sidebar_layout.addWidget(subtitle)

        navigation = QListWidget()
        navigation.setObjectName("navigation")
        navigation.setAccessibleName("Application navigation")
        for name in _NAVIGATION:
            item = QListWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole, name)
            navigation.addItem(item)
        navigation.setCurrentRow(0)
        navigation.currentRowChanged.connect(self._show_page)
        sidebar_layout.addWidget(navigation, stretch=1)

        content = QStackedWidget()
        content.setObjectName("content")
        for name in _NAVIGATION:
            page: QWidget
            if name == "Network Discovery":
                panel = ScanPanel(OperationType.DISCOVERY)
                panel.start_requested.connect(self._start_discovery)
                panel.cancel_requested.connect(
                    lambda panel=panel: self._cancel_panel_operation(panel)
                )
                self._discovery_panel = panel
                page = panel
            elif name == "Port Scanner":
                panel = ScanPanel(OperationType.PORT_SCAN)
                panel.start_requested.connect(self._start_port_scan)
                panel.cancel_requested.connect(
                    lambda panel=panel: self._cancel_panel_operation(panel)
                )
                self._port_scan_panel = panel
                page = panel
            elif name == "Network Monitor":
                monitor_panel = MonitorPanel()
                monitor_panel.start_requested.connect(self._start_monitoring)
                monitor_panel.stop_requested.connect(self._stop_monitoring)
                monitor_panel.refresh_requested.connect(self._refresh_monitor)
                self._monitor_panel = monitor_panel
                page = monitor_panel
            elif name == "Device Inventory":
                inventory_panel = InventoryPanel()
                inventory_panel.refresh_requested.connect(self._refresh_inventory)
                inventory_panel.export_csv_requested.connect(self._export_inventory_csv)
                inventory_panel.export_json_requested.connect(
                    self._export_inventory_json
                )
                self._inventory_panel = inventory_panel
                page = inventory_panel
            elif name == "Security Assessment":
                assessment_panel = AssessmentPanel()
                assessment_panel.assess_requested.connect(self._run_assessment)
                assessment_panel.export_csv_requested.connect(self._export_assessment_csv)
                assessment_panel.export_json_requested.connect(self._export_assessment_json)
                self._assessment_panel = assessment_panel
                page = assessment_panel
            else:
                page = self._placeholder_page(name)
            content.addWidget(page)
        self._content = content
        self._refresh_inventory("")

        layout.addWidget(sidebar)
        layout.addWidget(content, stretch=1)
        self.setCentralWidget(root)

    def _placeholder_page(self, section: str) -> QWidget:
        """Build an honest placeholder until the section is implemented."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(42, 42, 42, 42)
        layout.setSpacing(16)

        heading = QLabel(section)
        heading.setStyleSheet("font-size: 28px; font-weight: 700; color: #e0f2fe;")
        status = QLabel(
            "The application foundation is ready. "
            "This module will be delivered in a subsequent implementation stage."
        )
        status.setObjectName("status")
        status.setWordWrap(True)
        status.setMaximumWidth(720)
        layout.addWidget(heading)
        layout.addWidget(status)
        layout.addStretch(1)
        return page

    def _start_discovery(self, payload: object) -> None:
        if not isinstance(payload, ScanFormData):
            return
        self._start_operation(
            self._discovery_panel,
            payload,
            OperationType.DISCOVERY,
        )

    def _start_port_scan(self, payload: object) -> None:
        if not isinstance(payload, ScanFormData):
            return
        self._start_operation(
            self._port_scan_panel,
            payload,
            OperationType.PORT_SCAN,
        )

    def _start_monitoring(self, interval_ms: int) -> None:
        """Start periodic local telemetry refreshes without network probes."""
        self._monitor_timer.start(interval_ms)
        self._monitor_panel.set_monitoring(True)
        self._monitor_panel.set_status("Monitoring started.")
        self._refresh_monitor()

    def _stop_monitoring(self) -> None:
        """Stop periodic telemetry refreshes and keep the last snapshot visible."""
        self._monitor_timer.stop()
        self._monitor_panel.set_monitoring(False)
        self._monitor_panel.set_status("Monitoring stopped. Last sample retained.")

    def _refresh_monitor(self) -> None:
        """Read one local telemetry snapshot on the GUI timer boundary."""
        try:
            snapshot = self._monitor_service.refresh()
        except Exception as exc:
            self._monitor_panel.set_status(f"Monitoring unavailable: {exc}")
            return
        self._monitor_panel.set_snapshot(snapshot)

    def _refresh_inventory(self, search: str) -> None:
        """Load persisted assets into the inventory table."""
        try:
            assets = self._inventory_service.list_assets(search)
        except (OSError, sqlite3.Error) as exc:
            self._inventory_panel.set_status(f"Inventory unavailable: {exc}")
            return
        self._inventory_panel.set_assets(assets, search.strip())

    def _export_inventory_csv(self, search: str) -> None:
        """Choose a destination and export the current inventory as CSV."""
        path = self._choose_inventory_path("CSV", "inventory.csv")
        if path is None:
            return
        try:
            count = self._inventory_service.export_csv(path, search)
        except (OSError, ValueError, sqlite3.Error) as exc:
            self._inventory_panel.set_status(f"CSV export failed: {exc}")
            return
        self._inventory_panel.set_status(f"Exported {count} device(s) to {path}.")

    def _export_inventory_json(self, search: str) -> None:
        """Choose a destination and export the current inventory as JSON."""
        path = self._choose_inventory_path("JSON", "inventory.json")
        if path is None:
            return
        try:
            count = self._inventory_service.export_json(path, search)
        except (OSError, ValueError, sqlite3.Error) as exc:
            self._inventory_panel.set_status(f"JSON export failed: {exc}")
            return
        self._inventory_panel.set_status(f"Exported {count} device(s) to {path}.")

    def _choose_inventory_path(self, format_name: str, filename: str) -> Path | None:
        """Ask the operator for an export path without overwriting silently."""
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export inventory as {format_name}",
            str(self._config.report_directory / filename),
            f"{format_name} files (*.{format_name.lower()});;All files (*)",
        )
        return Path(path) if path else None

    def _run_assessment(self) -> None:
        """Run deterministic assessment rules against current evidence."""
        try:
            findings = self._assessment_service.assess()
        except (OSError, sqlite3.Error) as exc:
            self._assessment_panel.set_status(f"Assessment failed: {exc}")
            return
        self._assessment_panel.set_findings(findings)
        self._assessment_panel.set_status(
            f"Assessment completed. {len(findings)} finding(s) generated."
        )

    def _export_assessment_csv(self) -> None:
        """Choose a destination and export the current assessment as CSV."""
        path = self._choose_assessment_path("CSV", "assessment.csv")
        if path is None:
            return
        try:
            count = self._assessment_service.export_csv(path)
        except (OSError, ValueError, sqlite3.Error) as exc:
            self._assessment_panel.set_status(f"CSV export failed: {exc}")
            return
        self._assessment_panel.set_status(f"Exported {count} finding(s) to {path}.")

    def _export_assessment_json(self) -> None:
        """Choose a destination and export the current assessment as JSON."""
        path = self._choose_assessment_path("JSON", "assessment.json")
        if path is None:
            return
        try:
            count = self._assessment_service.export_json(path)
        except (OSError, ValueError, sqlite3.Error) as exc:
            self._assessment_panel.set_status(f"JSON export failed: {exc}")
            return
        self._assessment_panel.set_status(f"Exported {count} finding(s) to {path}.")

    def _choose_assessment_path(self, format_name: str, filename: str) -> Path | None:
        """Ask the operator for an export path without overwriting silently."""
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export assessment as {format_name}",
            str(self._config.report_directory / filename),
            f"{format_name} files (*.{format_name.lower()});;All files (*)",
        )
        return Path(path) if path else None

    def _start_operation(
        self,
        panel: ScanPanel,
        data: ScanFormData,
        operation: OperationType,
    ) -> None:
        """Validate, confirm, authorize, and enqueue one active operation."""
        if not data.confirmed:
            self._show_warning(
                "Authorization required",
                "Tick the authorization confirmation before starting an operation.",
            )
            return
        if not data.operator.strip() or not data.reason.strip():
            self._show_warning(
                "Authorization details required",
                "Operator identity and reason are required before starting.",
            )
            return

        try:
            scope = parse_scope(
                _split_values(data.targets),
                _split_values(data.exclusions),
                max_hosts=self._config.max_scope_hosts,
            )
            ports = (
                parse_ports(data.ports)
                if operation is OperationType.PORT_SCAN
                else ()
            )
            self._policy.validate_scope(scope)
            if operation is OperationType.PORT_SCAN:
                self._policy.validate_ports(ports)
        except NetSentinelError as exc:
            self._show_warning("Invalid operation", str(exc))
            return

        scope_summary = _scope_summary(scope)
        operation_name = (
            "network discovery"
            if operation is OperationType.DISCOVERY
            else "TCP port scan"
        )
        confirmation = QMessageBox.question(
            self,
            "Confirm authorized operation",
            f"Start {operation_name}?\n\n"
            f"Scope: {scope_summary}\n"
            f"Operator: {data.operator.strip()}\n"
            f"Reason: {data.reason.strip()}\n\n"
            "Only the normalized, policy-checked scope will be used.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            panel.set_status("Operation cancelled before it started.")
            return

        try:
            authorization = self._authorization.confirm(
                operator=data.operator,
                operation=operation,
                scope=scope,
                reason=data.reason,
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )
            self._repository.save_authorization(authorization)
        except (NetSentinelError, OSError, sqlite3.Error) as exc:
            self._show_warning("Authorization rejected", str(exc))
            return

        job_id = uuid4()
        function = self._operation_function(
            operation,
            authorization,
            scope,
            ports,
            data.interface.strip() or None,
            job_id,
        )
        worker = Worker(job_id, function)
        self._connect_worker(worker, panel)
        panel.set_running(True)
        panel.progress.setRange(0, 100)
        panel.progress.setValue(0)
        panel.set_status(f"{operation_name.capitalize()} queued.")
        self._active_panels[job_id] = panel
        try:
            self._worker_manager.start(worker)
        except ValueError as exc:
            self._active_panels.pop(job_id, None)
            panel.set_running(False)
            self._show_warning("Unable to start operation", str(exc))

    def _operation_function(
        self,
        operation: OperationType,
        authorization: AuthorizationRecord,
        scope: ScanScope,
        ports: tuple[int, ...],
        interface: str | None,
        job_id: UUID,
    ) -> Callable[..., object]:
        if operation is OperationType.DISCOVERY:
            return lambda cancellation, progress: self._discovery_service.run(
                scope=scope,
                authorization=authorization,
                interface=interface,
                cancellation=cancellation,
                job_id=job_id,
                progress=progress,
            )
        return lambda cancellation, progress: self._port_scan_service.run(
            scope=scope,
            ports=ports,
            authorization=authorization,
            cancellation=cancellation,
            job_id=job_id,
            progress=progress,
        )

    def _connect_worker(self, worker: Worker, panel: ScanPanel) -> None:
        job_id = worker.job_id
        worker.signals.progress.connect(
            lambda event, panel=panel: self._on_progress(panel, event)
        )
        worker.signals.result.connect(
            lambda result, panel=panel: self._on_result(panel, result)
        )
        worker.signals.error.connect(
            lambda event, panel=panel: self._on_error(panel, event)
        )
        worker.signals.cancelled.connect(
            lambda _job_id, panel=panel: panel.set_status(
                "Cancellation completed; partial results were not "
                "presented as complete."
            )
        )
        worker.signals.finished.connect(self._on_worker_finished)
        worker.signals.finished.connect(
            lambda _job_id, panel=panel: panel.set_running(False)
        )
        worker.signals.finished.connect(
            lambda _job_id, job_id=job_id: self._active_panels.pop(job_id, None)
        )

    def _on_progress(self, panel: ScanPanel, event: object) -> None:
        if isinstance(event, ProgressEvent):
            panel.set_progress(event.completed, event.total, event.message)

    def _on_result(self, panel: ScanPanel, result: object) -> None:
        count = (
            len(cast(tuple[object, ...], result))
            if isinstance(result, tuple)
            else 0
        )
        panel.progress.setRange(0, 1)
        panel.progress.setValue(1)
        panel.set_status(f"Operation completed successfully. Results: {count}.")
        if panel is self._discovery_panel:
            self._refresh_inventory(self._inventory_panel.search.text().strip())

    def _on_error(self, panel: ScanPanel, event: object) -> None:
        if isinstance(event, JobErrorEvent):
            panel.set_status(f"Operation failed: {event.message}")
        else:
            panel.set_status("Operation failed with an unexpected worker error.")

    def _on_worker_finished(self, job_id: object) -> None:
        if isinstance(job_id, UUID):
            panel = self._active_panels.get(job_id)
            if panel is not None:
                panel.set_running(False)

    def _cancel_panel_operation(self, panel: ScanPanel) -> None:
        for job_id, active_panel in tuple(self._active_panels.items()):
            if active_panel is panel:
                if self._worker_manager.cancel(job_id):
                    panel.set_status("Cancellation requested…")
                return

    def _show_page(self, index: int) -> None:
        self._content.setCurrentIndex(index)

    def _show_warning(self, title: str, message: str) -> None:
        QMessageBox.warning(self, title, message)

    def closeEvent(self, event: QCloseEvent) -> None:
        """Request cooperative cancellation before the application closes."""
        self._monitor_timer.stop()
        for job_id in self._worker_manager.active_job_ids:
            self._worker_manager.cancel(job_id)
        event.accept()

    def _load_stylesheet(self) -> None:
        """Load the repository stylesheet when running from a source checkout."""
        stylesheet = (
            Path(__file__).resolve().parents[3] / "assets" / "styles" / "dark.qss"
        )
        if stylesheet.is_file():
            self.setStyleSheet(stylesheet.read_text(encoding="utf-8"))


def _split_values(value: str) -> tuple[str, ...]:
    """Split comma-separated UI values while rejecting empty-only input later."""
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _scope_summary(scope: ScanScope) -> str:
    hosts = scope.hosts()
    preview = ", ".join(str(address) for address in hosts[:5])
    if len(hosts) > 5:
        preview += ", …"
    return f"{len(hosts)} host(s): {preview}"
