"""Minimal Qt shell for the first NetSentinel development stage."""

from __future__ import annotations

from pathlib import Path

from netsentinel.infrastructure.config import AppConfig
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)


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
    """Application shell with navigation reserved for later feature stages."""

    def __init__(self, config: AppConfig) -> None:
        super().__init__()
        self._config = config
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

        sidebar = QFrame(objectName="sidebar")
        sidebar.setFixedWidth(240)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 24, 20, 20)
        sidebar_layout.setSpacing(12)

        brand = QLabel("NETSENTINEL", objectName="brand")
        subtitle = QLabel("Defensive network visibility", objectName="subtitle")
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
            content.addWidget(self._placeholder_page(name))
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
            "This module will be delivered in a subsequent implementation stage.",
            objectName="status",
        )
        status.setWordWrap(True)
        status.setMaximumWidth(720)
        layout.addWidget(heading)
        layout.addWidget(status)
        layout.addStretch(1)
        return page

    def _show_page(self, index: int) -> None:
        self._content.setCurrentIndex(index)

    def _load_stylesheet(self) -> None:
        """Load the repository stylesheet when running from a source checkout."""
        stylesheet = (
            Path(__file__).resolve().parents[3] / "assets" / "styles" / "dark.qss"
        )
        if stylesheet.is_file():
            self.setStyleSheet(stylesheet.read_text(encoding="utf-8"))
