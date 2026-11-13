"""Main Qt window and coordination for authorized active operations."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
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

from netsentinel.application.authorization import AuthorizationService
from netsentinel.application.discovery import DiscoveryService
from netsentinel.application.events import JobErrorEvent, ProgressEvent
from netsentinel.application.policies import SafetyLimits, SafetyPolicy
from netsentinel.application.port_scanning import PortScanService
from netsentinel.domain.enums import OperationType
from netsentinel.domain.errors import NetSentinelError
from netsentinel.domain.models import AuthorizationRecord, ScanScope
from netsentinel.domain.validation import parse_ports, parse_scope
from netsentinel.infrastructure.config import AppConfig
from netsentinel.infrastructure.database.connection import SQLiteDatabase
from netsentinel.infrastructure.database.repositories import SQLiteRepository
from netsentinel.infrastructure.scanning.scapy_discovery import ScapyDiscoveryAdapter
from netsentinel.infrastructure.scanning.tcp_scanner import TcpConnectScanner
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
            else:
                page = self._placeholder_page(name)
            content.addWidget(page)
        self._content = content

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
