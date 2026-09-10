"""
CCIT Settings Panel
Application configuration: theme selection, scan parameters, logging, database management.
"""

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDoubleSpinBox,
                                QFormLayout, QFrame, QGroupBox, QHBoxLayout,
                                QLabel, QLineEdit, QPushButton, QScrollArea,
                                QSpinBox, QVBoxLayout, QWidget)

from modules.database import db
from modules.logger import logger
from ui.theme import theme_manager


class SettingsPanel(QWidget):
    """Application settings and configuration panel."""

    theme_changed = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        p = theme_manager.palette
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 20)
        root.setSpacing(14)

        title = QLabel("[ ⚙ ]  SETTINGS & CONFIGURATION")
        title.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 16px; font-weight: bold; letter-spacing: 3px;"
        )
        root.addWidget(title)
        sub = QLabel("Customize CCIT appearance, scanning behavior, logging, and database")
        sub.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        root.addWidget(sub)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(16)
        content_layout.setContentsMargins(0, 0, 12, 0)
        scroll.setWidget(content)
        root.addWidget(scroll, 1)

        content_layout.addWidget(self._make_ui_group())
        content_layout.addWidget(self._make_scanner_group())
        content_layout.addWidget(self._make_network_group())
        content_layout.addWidget(self._make_logging_group())
        content_layout.addWidget(self._make_database_group())
        content_layout.addWidget(self._make_update_group())
        content_layout.addStretch()

        btn_row = QHBoxLayout()
        save_btn = QPushButton("[ SAVE SETTINGS ]")
        save_btn.clicked.connect(self._save_settings)
        reset_btn = QPushButton("RESET DEFAULTS")
        reset_btn.clicked.connect(self._reset_defaults)
        btn_row.addWidget(save_btn)
        btn_row.addWidget(reset_btn)
        btn_row.addStretch()
        root.addLayout(btn_row)

    def _make_ui_group(self) -> QGroupBox:
        group = QGroupBox("USER INTERFACE")
        form = QFormLayout(group)
        form.setSpacing(10)

        self._theme_combo = QComboBox()
        self._theme_combo.addItems(theme_manager.available_themes())
        self._theme_combo.setCurrentText(theme_manager.name)
        self._theme_combo.currentTextChanged.connect(self._on_theme_change)

        self._animations_check = QCheckBox("Enable UI animations")
        self._animations_check.setChecked(True)

        self._font_size_spin = QSpinBox()
        self._font_size_spin.setRange(10, 18)
        self._font_size_spin.setValue(12)
        self._font_size_spin.setSuffix(" px")

        self._sidebar_width_spin = QSpinBox()
        self._sidebar_width_spin.setRange(180, 320)
        self._sidebar_width_spin.setValue(220)
        self._sidebar_width_spin.setSuffix(" px")

        form.addRow("Theme:", self._theme_combo)
        form.addRow("Font Size:", self._font_size_spin)
        form.addRow("Sidebar Width:", self._sidebar_width_spin)
        form.addRow("", self._animations_check)
        return group

    def _make_scanner_group(self) -> QGroupBox:
        group = QGroupBox("SCANNER SETTINGS")
        form = QFormLayout(group)
        form.setSpacing(10)

        self._timeout_spin = QDoubleSpinBox()
        self._timeout_spin.setRange(1.0, 60.0)
        self._timeout_spin.setValue(10.0)
        self._timeout_spin.setSuffix(" sec")
        self._timeout_spin.setDecimals(1)

        self._max_redirects_spin = QSpinBox()
        self._max_redirects_spin.setRange(0, 20)
        self._max_redirects_spin.setValue(5)

        self._verify_ssl_check = QCheckBox("Verify SSL certificates (disable to scan expired certs)")
        self._verify_ssl_check.setChecked(False)

        self._ua_input = QLineEdit()
        self._ua_input.setText("CCIT-Scanner/1.0")

        form.addRow("Request Timeout:", self._timeout_spin)
        form.addRow("Max Redirects:", self._max_redirects_spin)
        form.addRow("User-Agent:", self._ua_input)
        form.addRow("", self._verify_ssl_check)
        return group

    def _make_network_group(self) -> QGroupBox:
        group = QGroupBox("NETWORK MONITOR")
        form = QFormLayout(group)
        form.setSpacing(10)

        self._poll_interval_spin = QDoubleSpinBox()
        self._poll_interval_spin.setRange(0.5, 30.0)
        self._poll_interval_spin.setValue(2.0)
        self._poll_interval_spin.setSuffix(" sec")
        self._poll_interval_spin.setDecimals(1)

        self._max_conn_spin = QSpinBox()
        self._max_conn_spin.setRange(10, 1000)
        self._max_conn_spin.setValue(100)

        self._suspicious_threshold_spin = QSpinBox()
        self._suspicious_threshold_spin.setRange(1, 20)
        self._suspicious_threshold_spin.setValue(3)

        form.addRow("Poll Interval:", self._poll_interval_spin)
        form.addRow("Max Connections Displayed:", self._max_conn_spin)
        form.addRow("Suspicious Port Alert Threshold:", self._suspicious_threshold_spin)
        return group

    def _make_logging_group(self) -> QGroupBox:
        group = QGroupBox("LOGGING")
        form = QFormLayout(group)
        form.setSpacing(10)

        self._log_level_combo = QComboBox()
        self._log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self._log_level_combo.setCurrentText("INFO")

        self._log_max_size_spin = QSpinBox()
        self._log_max_size_spin.setRange(1, 500)
        self._log_max_size_spin.setValue(50)
        self._log_max_size_spin.setSuffix(" MB")

        self._console_log_check = QCheckBox("Enable console logging")
        self._console_log_check.setChecked(True)

        self._clear_logs_btn = QPushButton("CLEAR LOG FILES")
        self._clear_logs_btn.clicked.connect(self._clear_logs)

        form.addRow("Log Level:", self._log_level_combo)
        form.addRow("Max Log File Size:", self._log_max_size_spin)
        form.addRow("", self._console_log_check)
        form.addRow("", self._clear_logs_btn)
        return group

    def _make_database_group(self) -> QGroupBox:
        group = QGroupBox("DATABASE MANAGEMENT")
        form = QFormLayout(group)
        form.setSpacing(10)

        self._max_history_spin = QSpinBox()
        self._max_history_spin.setRange(50, 5000)
        self._max_history_spin.setValue(500)
        self._max_history_spin.setSuffix(" records")

        stats = db.get_stats()
        self._db_stats_label = QLabel(
            f"Scans: {stats.get('total_scans',0)}  |  "
            f"Threats: {stats.get('threats_found',0)}  |  "
            f"Network Events: {stats.get('network_events',0)}"
        )
        self._db_stats_label.setStyleSheet("color: #888; font-size: 10px;")

        self._seed_demo_btn = QPushButton("SEED DEMO DATA")
        self._seed_demo_btn.clicked.connect(self._seed_demo)
        self._clear_db_btn = QPushButton("CLEAR SCAN HISTORY")
        self._clear_db_btn.setProperty("class", "danger")
        self._clear_db_btn.clicked.connect(self._clear_history)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self._seed_demo_btn)
        btn_row.addWidget(self._clear_db_btn)
        btn_row.addStretch()

        form.addRow("Max Scan History:", self._max_history_spin)
        form.addRow("DB Stats:", self._db_stats_label)
        form.addRow("", btn_row)
        return group

    def _make_update_group(self) -> QGroupBox:
        group = QGroupBox("UPDATES")
        form = QFormLayout(group)
        form.setSpacing(10)

        self._offline_mode_check = QCheckBox("Offline mode (no update checks)")
        self._offline_mode_check.setChecked(True)

        self._check_startup_check = QCheckBox("Check for updates on startup")
        self._check_startup_check.setChecked(False)

        self._update_url_input = QLineEdit()
        self._update_url_input.setPlaceholderText("https://example.com/ccit/version.json")
        self._update_url_input.setEnabled(False)
        self._offline_mode_check.toggled.connect(
            lambda checked: self._update_url_input.setEnabled(not checked)
        )

        form.addRow("", self._offline_mode_check)
        form.addRow("", self._check_startup_check)
        form.addRow("Update URL:", self._update_url_input)
        return group

    def _on_theme_change(self, theme_name: str) -> None:
        new_sheet = theme_manager.set_theme(theme_name)
        if self.window():
            self.window().setStyleSheet(new_sheet)
        self.theme_changed.emit(theme_name)
        logger.info(f"Theme changed to: {theme_name}", module="SETTINGS")

    def _load_settings(self) -> None:
        stored_theme = db.get_setting("theme", "neon_dark")
        if stored_theme in theme_manager.available_themes():
            self._theme_combo.setCurrentText(stored_theme)

    def _save_settings(self) -> None:
        db.set_setting("theme", self._theme_combo.currentText())
        db.set_setting("scan_timeout", self._timeout_spin.value())
        db.set_setting("max_redirects", self._max_redirects_spin.value())
        db.set_setting("log_level", self._log_level_combo.currentText())
        db.set_setting("offline_mode", self._offline_mode_check.isChecked())
        logger.info("Settings saved", module="SETTINGS")

        stats = db.get_stats()
        self._db_stats_label.setText(
            f"Scans: {stats.get('total_scans',0)}  |  "
            f"Threats: {stats.get('threats_found',0)}  |  "
            f"Network Events: {stats.get('network_events',0)}"
        )

    def _reset_defaults(self) -> None:
        self._theme_combo.setCurrentText("neon_dark")
        self._timeout_spin.setValue(10.0)
        self._max_redirects_spin.setValue(5)
        self._log_level_combo.setCurrentText("INFO")
        self._offline_mode_check.setChecked(True)
        logger.info("Settings reset to defaults", module="SETTINGS")

    def _clear_logs(self) -> None:
        logger.clear_scan_log()
        logger.info("Scan log cleared", module="SETTINGS")

    def _seed_demo(self) -> None:
        db.seed_demo_data()
        stats = db.get_stats()
        self._db_stats_label.setText(
            f"Scans: {stats.get('total_scans',0)}  |  "
            f"Threats: {stats.get('threats_found',0)}  |  "
            f"Network Events: {stats.get('network_events',0)}"
        )
        logger.info("Demo data seeded", module="SETTINGS")

    def _clear_history(self) -> None:
        db.clear_scan_history()
        self._db_stats_label.setText("Scans: 0  |  Threats: 0  |  Network Events: 0")
        logger.info("Scan history cleared", module="SETTINGS")
