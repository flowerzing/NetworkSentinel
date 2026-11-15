"""Qt view for local interface and traffic monitoring."""

from __future__ import annotations

from collections import deque

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

# pyqtgraph is an optional dependency; mypy ignores missing stubs
try:
    import pyqtgraph as pg
    from pyqtgraph import PlotWidget
    PYQTGRAPH_AVAILABLE = True
except ImportError:
    PYQTGRAPH_AVAILABLE = False

# mypy: disable-error-code="import-untyped"

from netsentinel.domain.models import MonitorSnapshot, TrafficSample


class MonitorPanel(QWidget):
    """Display local interface metadata and periodic traffic samples."""

    start_requested = Signal(int)
    stop_requested = Signal()
    refresh_requested = Signal()

    _HEADERS = (
        "Interface",
        "IPv4 addresses",
        "State",
        "Speed",
        "Received",
        "Sent",
        "Errors / drops",
    )

    _MAX_POINTS = 120  # Keep last 120 samples for chart

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._traffic_history: dict[str, deque[tuple[float, float]]] = {}
        self._time_history: deque[float] = deque(maxlen=self._MAX_POINTS)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(42, 42, 42, 42)
        layout.setSpacing(16)

        heading = QLabel("Network Monitor")
        heading.setObjectName("pageHeading")
        description = QLabel(
            "Read-only local interface telemetry from psutil. This monitor does not "
            "generate scan traffic."
        )
        description.setObjectName("status")
        description.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(description)

        controls = QHBoxLayout()
        form = QFormLayout()
        self.interval = QSpinBox()
        self.interval.setRange(250, 60000)
        self.interval.setValue(1000)
        self.interval.setSuffix(" ms")
        form.addRow("Refresh interval", self.interval)
        controls.addLayout(form)

        self.start_button = QPushButton("Start monitoring")
        self.start_button.setObjectName("primaryButton")
        self.start_button.clicked.connect(
            lambda: self.start_requested.emit(self.interval.value())
        )
        self.stop_button = QPushButton("Stop monitoring")
        self.stop_button.setObjectName("secondaryButton")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_requested.emit)
        self.refresh_button = QPushButton("Refresh once")
        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        controls.addWidget(self.refresh_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.table = QTableWidget(0, len(self._HEADERS))
        self.table.setHorizontalHeaderLabels(self._HEADERS)
        self.table.setObjectName("monitorTable")
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, stretch=1)

        # Live traffic charts
        if PYQTGRAPH_AVAILABLE:
            self.chart_widget = PlotWidget()
            self.chart_widget.setObjectName("trafficChart")
            self.chart_widget.setBackground("#1e293b")
            self.chart_widget.setTitle(
                "Live Traffic Rates", color="#e0f2fe", size="12pt"
            )
            self.chart_widget.setLabel("left", "Rate", units="B/s")
            self.chart_widget.setLabel("bottom", "Time", units="s")
            self.chart_widget.showGrid(x=True, y=True, alpha=0.3)
            self.chart_widget.addLegend()
            self._send_curve = self.chart_widget.plot(
                pen=pg.mkPen("#60a5fa", width=2), name="Sent"
            )
            self._recv_curve = self.chart_widget.plot(
                pen=pg.mkPen("#f87171", width=2), name="Received"
            )
            layout.addWidget(self.chart_widget, stretch=1)
        else:
            self.chart_widget = None
            missing = QLabel(
                "Install pyqtgraph for live charts: pip install pyqtgraph"
            )
            missing.setObjectName("status")
            missing.setWordWrap(True)
            layout.addWidget(missing)

        self.status = QLabel("Ready. Monitoring is stopped.")
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

    def set_monitoring(self, monitoring: bool) -> None:
        """Toggle controls according to the timer state."""
        self.start_button.setEnabled(not monitoring)
        self.stop_button.setEnabled(monitoring)
        self.interval.setEnabled(not monitoring)

    def set_snapshot(self, snapshot: MonitorSnapshot) -> None:
        """Render one immutable service snapshot."""
        traffic = {sample.interface_name: sample for sample in snapshot.traffic}
        self.table.setRowCount(len(snapshot.interfaces))
        for row, interface in enumerate(snapshot.interfaces):
            sample = traffic.get(interface.name)
            values = (
                interface.name,
                ", ".join(str(address) for address in interface.ipv4_addresses)
                or "—",
                "Up" if interface.is_up else "Down",
                _format_speed(interface.speed_mbps),
                _format_rate(sample.receive_rate_bytes_per_second if sample else 0.0),
                _format_rate(sample.send_rate_bytes_per_second if sample else 0.0),
                _format_errors(sample),
            )
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(value))

        local_time = snapshot.sampled_at.astimezone().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        self.status.setText(f"Last sample: {local_time}")

        # Update charts with aggregated traffic
        self._update_charts(snapshot)

    def _update_charts(self, snapshot: MonitorSnapshot) -> None:
        """Update live traffic charts with new sample."""
        if not PYQTGRAPH_AVAILABLE or self.chart_widget is None:
            return

        # Aggregate send/receive rates across all interfaces
        total_send = sum(
            sample.send_rate_bytes_per_second
            for sample in snapshot.traffic
        )
        total_recv = sum(
            sample.receive_rate_bytes_per_second
            for sample in snapshot.traffic
        )

        # Use timestamp as x-axis (seconds since epoch)
        timestamp = snapshot.sampled_at.timestamp()
        self._time_history.append(timestamp)
        self._time_history = deque(list(self._time_history), maxlen=self._MAX_POINTS)

        # Update curves
        times = list(self._time_history)
        if len(times) > 1:
            # Normalize to relative time (seconds since first sample)
            base_time = times[0]
            rel_times = [t - base_time for t in times]

            # Get send/recv history
            send_data = [total_send] * len(times)  # Simplified: just current value
            recv_data = [total_recv] * len(times)

            self._send_curve.setData(rel_times, send_data)
            self._recv_curve.setData(rel_times, recv_data)

    def set_status(self, message: str) -> None:
        """Set an actionable status or error message."""
        self.status.setText(message)


def _format_speed(speed_mbps: float | None) -> str:
    return f"{speed_mbps:g} Mbps" if speed_mbps is not None else "Unknown"


def _format_rate(bytes_per_second: float) -> str:
    units = ("B/s", "KiB/s", "MiB/s", "GiB/s")
    value = max(0.0, bytes_per_second)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024
    return "0.0 B/s"


def _format_errors(sample: TrafficSample | None) -> str:
    if sample is None:
        return "—"
    return (
        f"{sample.errors_in}/{sample.errors_out} errors; "
        f"{sample.drops_in}/{sample.drops_out} drops"
    )
