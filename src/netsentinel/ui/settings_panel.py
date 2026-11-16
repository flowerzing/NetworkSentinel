"""Qt view for application settings."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal, QSettings
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QDoubleSpinBox,
    QVBoxLayout,
    QWidget,
)


class SettingsPanel(QWidget):
    """Application settings with persistent storage."""

    settings_changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings = QSettings("NetSentinel", "NetSentinel")
        self._build_ui()
        self._load_settings()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(42, 42, 42, 42)
        layout.setSpacing(16)

        heading = QLabel("Settings")
        heading.setObjectName("pageHeading")
        description = QLabel(
            "Configure application paths, safety limits, and optional features. "
            "Changes are saved automatically and persist across restarts."
        )
        description.setObjectName("status")
        description.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(description)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)

        # Data directory
        self.data_dir = QLineEdit()
        self.data_dir.setReadOnly(True)
        btn_data = QPushButton("Browse…")
        btn_data.clicked.connect(lambda: self._choose_dir(self.data_dir, "Data Directory"))
        hbox = QHBoxLayout()
        hbox.addWidget(self.data_dir)
        hbox.addWidget(btn_data)
        form.addRow("Data directory", hbox)

        # Report directory
        self.report_dir = QLineEdit()
        self.report_dir.setReadOnly(True)
        btn_report = QPushButton("Browse…")
        btn_report.clicked.connect(lambda: self._choose_dir(self.report_dir, "Report Directory"))
        hbox = QHBoxLayout()
        hbox.addWidget(self.report_dir)
        hbox.addWidget(btn_report)
        form.addRow("Report directory", hbox)

        # Database path
        self.database_path = QLineEdit()
        self.database_path.setReadOnly(True)
        btn_db = QPushButton("Browse…")
        btn_db.clicked.connect(lambda: self._choose_file(self.database_path, "SQLite Database", "SQLite (*.sqlite3 *.db);;All files (*)"))
        hbox = QHBoxLayout()
        hbox.addWidget(self.database_path)
        hbox.addWidget(btn_db)
        form.addRow("Database path", hbox)

        # Nmap path
        self.nmap_path = QLineEdit()
        self.nmap_path.setPlaceholderText("Optional: path to nmap.exe")
        btn_nmap = QPushButton("Browse…")
        btn_nmap.clicked.connect(lambda: self._choose_file(self.nmap_path, "Nmap Executable", "Executable (nmap.exe)"))
        hbox = QHBoxLayout()
        hbox.addWidget(self.nmap_path)
        hbox.addWidget(btn_nmap)
        form.addRow("Nmap path", hbox)

        # Log level
        self.log_level = QLineEdit()
        self.log_level.setPlaceholderText("DEBUG, INFO, WARNING, ERROR, CRITICAL")
        form.addRow("Log level", self.log_level)

        # Safety limits section
        limits_label = QLabel("Safety Limits")
        limits_label.setStyleSheet("font-size: 16px; font-weight: 600; color: #e0f2fe; margin-top: 8px;")
        form.addRow(limits_label)

        self.max_scope_hosts = QSpinBox()
        self.max_scope_hosts.setRange(1, 65535)
        self.max_scope_hosts.setValue(256)
        form.addRow("Max scope hosts", self.max_scope_hosts)

        self.max_ports = QSpinBox()
        self.max_ports.setRange(1, 65535)
        self.max_ports.setValue(1024)
        form.addRow("Max ports per scan", self.max_ports)

        self.max_concurrency = QSpinBox()
        self.max_concurrency.setRange(1, 256)
        self.max_concurrency.setValue(16)
        form.addRow("Max concurrency", self.max_concurrency)

        self.max_rate_per_second = QDoubleSpinBox()
        self.max_rate_per_second.setRange(0.1, 1000.0)
        self.max_rate_per_second.setValue(25.0)
        self.max_rate_per_second.setSuffix(" /s")
        form.addRow("Max rate (operations/sec)", self.max_rate_per_second)

        self.connect_timeout = QDoubleSpinBox()
        self.connect_timeout.setRange(0.1, 60.0)
        self.connect_timeout.setValue(1.5)
        self.connect_timeout.setSuffix(" s")
        form.addRow("Connect timeout", self.connect_timeout)

        # Buttons
        buttons = QHBoxLayout()
        self.save_button = QPushButton("Save Settings")
        self.save_button.setObjectName("primaryButton")
        self.save_button.clicked.connect(self._save_settings)
        self.reset_button = QPushButton("Reset to Defaults")
        self.reset_button.setObjectName("secondaryButton")
        self.reset_button.clicked.connect(self._reset_defaults)
        buttons.addWidget(self.save_button)
        buttons.addWidget(self.reset_button)
        buttons.addStretch(1)
        form.addRow(buttons)

        layout.addLayout(form)
        layout.addStretch(1)

        self.status = QLabel("Ready. Settings loaded from persistent storage.")
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

    def _choose_dir(self, line_edit: QLineEdit, title: str) -> None:
        path = QFileDialog.getExistingDirectory(self, title, line_edit.text() or str(Path.home()))
        if path:
            line_edit.setText(path)
            self.status.setText(f"Selected {title}: {path}")

    def _choose_file(self, line_edit: QLineEdit, title: str, filter_str: str) -> None:
        path, _ = QFileDialog.getOpenFileName(self, title, line_edit.text() or str(Path.home()), filter_str)
        if path:
            line_edit.setText(path)
            self.status.setText(f"Selected {title}: {path}")

    def _load_settings(self) -> None:
        """Load settings from QSettings."""
        self.data_dir.setText(self._settings.value("data_dir", ""))
        self.report_dir.setText(self._settings.value("report_dir", ""))
        self.database_path.setText(self._settings.value("database_path", ""))
        self.nmap_path.setText(self._settings.value("nmap_path", ""))
        self.log_level.setText(self._settings.value("log_level", "INFO"))
        self.max_scope_hosts.setValue(int(self._settings.value("max_scope_hosts", 256)))
        self.max_ports.setValue(int(self._settings.value("max_ports", 1024)))
        self.max_concurrency.setValue(int(self._settings.value("max_concurrency", 16)))
        self.max_rate_per_second.setValue(float(self._settings.value("max_rate_per_second", 25.0)))
        self.connect_timeout.setValue(float(self._settings.value("connect_timeout_seconds", 1.5)))

    def _save_settings(self) -> None:
        """Save settings to QSettings."""
        self._settings.setValue("data_dir", self.data_dir.text())
        self._settings.setValue("report_dir", self.report_dir.text())
        self._settings.setValue("database_path", self.database_path.text())
        self._settings.setValue("nmap_path", self.nmap_path.text())
        self._settings.setValue("log_level", self.log_level.text().upper())
        self._settings.setValue("max_scope_hosts", self.max_scope_hosts.value())
        self._settings.setValue("max_ports", self.max_ports.value())
        self._settings.setValue("max_concurrency", self.max_concurrency.value())
        self._settings.setValue("max_rate_per_second", self.max_rate_per_second.value())
        self._settings.setValue("connect_timeout_seconds", self.connect_timeout.value())
        self._settings.sync()
        self.status.setText("Settings saved successfully.")
        self.settings_changed.emit()

    def _reset_defaults(self) -> None:
        """Reset all settings to defaults."""
        reply = QMessageBox.question(
            self,
            "Reset to defaults?",
            "This will clear all custom settings and restore defaults. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._settings.clear()
            self._load_settings()
            self.status.setText("Settings reset to defaults.")

    def get_settings_dict(self) -> dict:
        """Return current settings as a dictionary for programmatic access."""
        return {
            "data_dir": self.data_dir.text(),
            "report_dir": self.report_dir.text(),
            "database_path": self.database_path.text(),
            "nmap_path": self.nmap_path.text() or None,
            "log_level": self.log_level.text().upper(),
            "max_scope_hosts": self.max_scope_hosts.value(),
            "max_ports": self.max_ports.value(),
            "max_concurrency": self.max_concurrency.value(),
            "max_rate_per_second": self.max_rate_per_second.value(),
            "connect_timeout_seconds": self.connect_timeout.value(),
        }


# Qt imports at the bottom to avoid circular imports
from PySide6.QtCore import Qt