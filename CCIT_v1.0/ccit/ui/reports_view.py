"""
CCIT Reports View Page
Lists all generated reports, shows scan history, and provides export controls.
"""

import os
import subprocess
import sys
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QPushButton,
                                QSplitter, QTabWidget, QTableWidget,
                                QTableWidgetItem, QVBoxLayout, QWidget)

from modules.database import db
from modules.report_generator import ReportGenerator
from ui.theme import theme_manager
from ui.widgets import StatCard, TerminalLogWidget


class ReportsViewPage(QWidget):
    """Reports viewer and scan history browser."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._reporter = ReportGenerator()
        self._setup_ui()
        self._refresh()

    def _setup_ui(self) -> None:
        p = theme_manager.palette
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        title = QLabel("[ ▤ ]  REPORTS & SCAN HISTORY")
        title.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 16px; font-weight: bold; letter-spacing: 3px;"
        )
        sub = QLabel("View generated reports, browse scan history, and export findings")
        sub.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        root.addWidget(title)
        root.addWidget(sub)

        btn_row = QHBoxLayout()
        self._refresh_btn = QPushButton("[ REFRESH ]")
        self._refresh_btn.clicked.connect(self._refresh)
        self._export_all_btn = QPushButton("EXPORT ALL HISTORY")
        self._export_all_btn.clicked.connect(self._export_all)
        self._open_dir_btn = QPushButton("OPEN REPORTS DIR")
        self._open_dir_btn.clicked.connect(self._open_reports_dir)
        for w in (self._refresh_btn, self._export_all_btn, self._open_dir_btn):
            btn_row.addWidget(w)
        btn_row.addStretch()
        root.addLayout(btn_row)

        stats_row = QHBoxLayout()
        self._stat_total   = StatCard("TOTAL SCANS",  "0", accent_color=p.accent_primary)
        self._stat_threats = StatCard("THREATS FOUND","0", accent_color=p.accent_secondary)
        self._stat_net     = StatCard("NET EVENTS",   "0", accent_color=p.accent_tertiary)
        self._stat_reports = StatCard("REPORTS",      "0", accent_color=p.accent_warn)
        for c in (self._stat_total, self._stat_threats, self._stat_net, self._stat_reports):
            stats_row.addWidget(c)
        root.addLayout(stats_row)

        tabs = QTabWidget()

        self._history_table = QTableWidget(0, 6)
        self._history_table.setHorizontalHeaderLabels(
            ["#", "Type", "Target", "Verdict", "Score", "Timestamp"]
        )
        self._history_table.horizontalHeader().setStretchLastSection(True)
        self._history_table.verticalHeader().setVisible(False)
        self._history_table.setAlternatingRowColors(True)
        self._history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._history_table.doubleClicked.connect(self._on_history_double_click)

        self._reports_table = QTableWidget(0, 4)
        self._reports_table.setHorizontalHeaderLabels(["Title", "Type", "Format", "Created At"])
        self._reports_table.horizontalHeader().setStretchLastSection(True)
        self._reports_table.verticalHeader().setVisible(False)
        self._reports_table.setAlternatingRowColors(True)
        self._reports_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._reports_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._reports_table.doubleClicked.connect(self._on_report_double_click)

        self._indicators_table = QTableWidget(0, 4)
        self._indicators_table.setHorizontalHeaderLabels(["Indicator", "Type", "Threat Level", "Description"])
        self._indicators_table.horizontalHeader().setStretchLastSection(True)
        self._indicators_table.verticalHeader().setVisible(False)
        self._indicators_table.setAlternatingRowColors(True)
        self._indicators_table.setEditTriggers(QTableWidget.NoEditTriggers)

        self._log_widget = TerminalLogWidget()

        tabs.addTab(self._wrap(self._history_table), "SCAN HISTORY")
        tabs.addTab(self._wrap(self._reports_table), "GENERATED REPORTS")
        tabs.addTab(self._wrap(self._indicators_table), "THREAT INDICATORS")
        tabs.addTab(self._log_widget, "ACTIVITY LOG")

        root.addWidget(tabs, 1)
        self._log_widget.append_line("Reports view loaded.", "INFO")

    def _refresh(self) -> None:
        stats = db.get_stats()
        self._stat_total.set_value(str(stats.get("total_scans", 0)))
        self._stat_threats.set_value(str(stats.get("threats_found", 0)))
        self._stat_net.set_value(str(stats.get("network_events", 0)))

        scans = db.get_scan_history(limit=200)
        self._history_table.setRowCount(0)
        for scan in scans:
            row = self._history_table.rowCount()
            self._history_table.insertRow(row)
            self._history_table.setItem(row, 0, QTableWidgetItem(str(scan.get("id", ""))))
            self._history_table.setItem(row, 1, QTableWidgetItem(scan.get("scan_type", "")))
            self._history_table.setItem(row, 2, QTableWidgetItem(scan.get("target", "")[:60]))
            verdict = scan.get("result", "")
            v_item = QTableWidgetItem(verdict)
            color_map = {
                "MALICIOUS": "#FF0055", "HIGH_RISK": "#FF6600", "PHISHING": "#FF0055",
                "SUSPICIOUS": "#FFAA00", "CLEAN": "#00FF41", "LOW_RISK": "#AAFF00",
            }
            if verdict in color_map:
                v_item.setForeground(Qt.GlobalColor(0))
            self._history_table.setItem(row, 3, v_item)
            score = scan.get("threat_score", 0)
            score_item = QTableWidgetItem(f"{score}/100")
            self._history_table.setItem(row, 4, score_item)
            self._history_table.setItem(row, 5, QTableWidgetItem(scan.get("created_at", "")[:19]))

        reports = db.get_reports()
        self._stat_reports.set_value(str(len(reports)))
        self._reports_table.setRowCount(0)
        for rep in reports:
            row = self._reports_table.rowCount()
            self._reports_table.insertRow(row)
            self._reports_table.setItem(row, 0, QTableWidgetItem(rep.get("title", "")))
            self._reports_table.setItem(row, 1, QTableWidgetItem(rep.get("report_type", "")))
            self._reports_table.setItem(row, 2, QTableWidgetItem(rep.get("format", "")))
            self._reports_table.setItem(row, 3, QTableWidgetItem(rep.get("created_at", "")[:19]))

        indicators = db.get_all_indicators()
        self._indicators_table.setRowCount(0)
        for ind in indicators:
            row = self._indicators_table.rowCount()
            self._indicators_table.insertRow(row)
            self._indicators_table.setItem(row, 0, QTableWidgetItem(ind.get("indicator", "")))
            self._indicators_table.setItem(row, 1, QTableWidgetItem(ind.get("ioc_type", "")))
            level = ind.get("threat_level", "")
            level_item = QTableWidgetItem(level)
            self._indicators_table.setItem(row, 2, level_item)
            self._indicators_table.setItem(row, 3, QTableWidgetItem(ind.get("description", "")))

        self._log_widget.append_line(
            f"Refreshed — {len(scans)} scans, {len(reports)} reports, {len(indicators)} indicators",
            "INFO",
        )

    def _export_all(self) -> None:
        scans = db.get_scan_history(limit=500)
        if not scans:
            self._log_widget.append_line("No scan history to export.", "WARNING")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Scan History", "ccit_history.json", "JSON Files (*.json)"
        )
        if path:
            import json
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(scans, fh, indent=2, default=str)
            self._log_widget.append_line(f"History exported to: {path}", "INFO")

    def _open_reports_dir(self) -> None:
        reports_dir = os.path.abspath("reports")
        os.makedirs(reports_dir, exist_ok=True)
        if sys.platform == "win32":
            os.startfile(reports_dir)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", reports_dir])
        else:
            subprocess.Popen(["xdg-open", reports_dir])

    def _on_history_double_click(self, index) -> None:
        row = index.row()
        scan_id = self._history_table.item(row, 0)
        target = self._history_table.item(row, 2)
        if scan_id and target:
            self._log_widget.append_line(
                f"Scan #{scan_id.text()} — Target: {target.text()}", "INFO"
            )

    def _on_report_double_click(self, index) -> None:
        row = index.row()
        title_item = self._reports_table.item(row, 0)
        if title_item:
            reports = db.get_reports()
            if row < len(reports):
                file_path = reports[row].get("file_path", "")
                if file_path and os.path.isfile(file_path):
                    if sys.platform == "win32":
                        os.startfile(file_path)
                    elif sys.platform == "darwin":
                        subprocess.Popen(["open", file_path])
                    else:
                        subprocess.Popen(["xdg-open", file_path])

    @staticmethod
    def _wrap(w: QWidget) -> QWidget:
        c = QWidget()
        l = QVBoxLayout(c)
        l.setContentsMargins(0, 0, 0, 0)
        l.addWidget(w)
        return c
