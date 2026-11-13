"""Qt tests for the authorized discovery, scan, and monitor controls."""

from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

from PySide6.QtWidgets import QMessageBox

from netsentinel.application.discovery import DiscoveryService
from netsentinel.domain.models import (
    DiscoveryRecord,
    InterfaceInfo,
    MonitorSnapshot,
    TrafficSample,
)
from netsentinel.infrastructure.config import AppConfig
from netsentinel.ui.main_window import MainWindow
from netsentinel.ui.monitor_panel import MonitorPanel


class FakeDiscoveryAdapter:
    def discover(self, scope, *, interface=None, cancellation=None):
        return (
            DiscoveryRecord(
                address=IPv4Address("192.168.50.1"),
                observed_at=datetime.now(UTC),
            ),
        )


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        data_directory=tmp_path / "data",
        report_directory=tmp_path / "reports",
        database_path=tmp_path / "data" / "netsentinel.sqlite3",
        nmap_path=None,
        log_level="INFO",
        max_scope_hosts=16,
        max_ports=32,
        max_concurrency=2,
        max_rate_per_second=100.0,
        connect_timeout_seconds=0.1,
    )


def test_main_window_exposes_active_operation_panels(qtbot, tmp_path: Path) -> None:
    window = MainWindow(_config(tmp_path))
    qtbot.addWidget(window)

    assert window._discovery_panel.start_button.isEnabled()
    assert window._port_scan_panel.start_button.isEnabled()
    assert window._monitor_panel.start_button.isEnabled()
    assert window._discovery_panel.cancel_button.isEnabled() is False
    assert window._port_scan_panel.cancel_button.isEnabled() is False
    assert window._worker_manager.active_job_ids == ()


def test_authorized_discovery_runs_in_worker_with_fake_adapter(
    qtbot, tmp_path: Path, monkeypatch
) -> None:
    window = MainWindow(_config(tmp_path))
    qtbot.addWidget(window)
    window._discovery_service = DiscoveryService(
        window._policy,
        FakeDiscoveryAdapter(),
        window._repository,
    )
    panel = window._discovery_panel
    panel.targets.setText("192.168.50.1")
    panel.operator.setText("test operator")
    panel.reason.setText("authorized test inventory")
    panel.confirmation.setChecked(True)
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )

    with qtbot.waitSignal(window._worker_manager.worker_finished, timeout=3000):
        panel.start_button.click()

    assert panel.start_button.isEnabled()
    assert "completed successfully" in panel.status.text()
    assert len(window._repository.list_assets()) == 1
    assert window._repository.list_assets()[0].address == IPv4Address(
        "192.168.50.1"
    )


def test_port_panel_requires_explicit_confirmation(
    qtbot, tmp_path: Path, monkeypatch
) -> None:
    window = MainWindow(_config(tmp_path))
    qtbot.addWidget(window)
    panel = window._port_scan_panel
    panel.targets.setText("192.168.50.1")
    panel.ports.setText("80")
    panel.operator.setText("test operator")
    panel.reason.setText("authorized test scan")
    warnings: list[str] = []
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append(message),
    )

    panel.start_button.click()

    assert warnings == [
        "Tick the authorization confirmation before starting an operation."
    ]
    assert window._worker_manager.active_job_ids == ()


def test_monitor_panel_renders_a_fake_snapshot(qtbot) -> None:
    panel = MonitorPanel()
    qtbot.addWidget(panel)

    panel.set_snapshot(
        MonitorSnapshot(
            sampled_at=datetime(2026, 1, 1, 12, tzinfo=UTC),
            interfaces=(
                InterfaceInfo(
                    name="Ethernet",
                    ipv4_addresses=(IPv4Address("192.168.1.10"),),
                    is_up=True,
                ),
            ),
            traffic=(
                TrafficSample(
                    interface_name="Ethernet",
                    sampled_at=datetime(2026, 1, 1, 12, tzinfo=UTC),
                    bytes_sent=10,
                    bytes_received=20,
                    packets_sent=1,
                    packets_received=2,
                    send_rate_bytes_per_second=100.0,
                    receive_rate_bytes_per_second=200.0,
                ),
            ),
        )
    )

    assert panel.table.rowCount() == 1
    assert panel.table.item(0, 0).text() == "Ethernet"
    assert "100.0 B/s" in panel.table.item(0, 5).text()
