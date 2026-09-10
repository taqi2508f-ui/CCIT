"""
CCIT Phishing Scanner Page
UI for phishing website analysis: URL input, SSL check, form extraction, script detection.
"""

import threading
from typing import Optional

from PySide6.QtCore import Qt, QTimer, Signal, QObject
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLineEdit,
                                QPushButton, QScrollArea, QSplitter,
                                QTabWidget, QTableWidget, QTableWidgetItem,
                                QVBoxLayout, QWidget)

from modules.url_analyzer import URLAnalyzer, URLAnalysisResult
from modules.report_generator import ReportGenerator
from modules.database import db
from ui.theme import theme_manager
from ui.widgets import (IndicatorListWidget, ScanSpinner, StatCard,
                        TerminalLogWidget, ThreatScoreGauge, VerdictBadge)


class _ScanSignals(QObject):
    finished = Signal(object)
    log = Signal(str, str)


class PhishingScannerPage(QWidget):
    """Full phishing website scanner page."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._analyzer = URLAnalyzer()
        self._reporter = ReportGenerator()
        self._signals = _ScanSignals()
        self._signals.finished.connect(self._on_scan_done)
        self._signals.log.connect(self._on_log)
        self._current_result: Optional[URLAnalysisResult] = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        p = theme_manager.palette
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        title_row = QHBoxLayout()
        title = QLabel("[ ⛓ ]  PHISHING WEBSITE SCANNER")
        title.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 16px; font-weight: bold; letter-spacing: 3px;"
        )
        sub = QLabel("Analyze URLs for phishing, credential theft, and malicious scripts")
        sub.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        title_row.addWidget(title)
        title_row.addStretch()
        root.addLayout(title_row)
        root.addWidget(sub)

        input_frame = QFrame()
        input_frame.setStyleSheet(
            f"QFrame {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: 2px; }}"
        )
        input_layout = QHBoxLayout(input_frame)
        input_layout.setContentsMargins(12, 10, 12, 10)
        input_layout.setSpacing(10)

        url_label = QLabel("TARGET URL:")
        url_label.setStyleSheet(f"color: {p.accent_primary}; font-size: 11px; font-weight: bold; min-width: 90px;")
        self._url_input = QLineEdit()
        self._url_input.setPlaceholderText("https://example.com  or  http://suspicious-site.tk/login")
        self._url_input.returnPressed.connect(self._start_scan)

        self._scan_btn = QPushButton("[ SCAN ]")
        self._scan_btn.setFixedWidth(100)
        self._scan_btn.clicked.connect(self._start_scan)

        self._demo_btn = QPushButton("DEMO")
        self._demo_btn.setFixedWidth(70)
        self._demo_btn.setToolTip("Load a demo phishing URL for demonstration")
        self._demo_btn.clicked.connect(self._load_demo)

        self._spinner = ScanSpinner(32)
        input_layout.addWidget(url_label)
        input_layout.addWidget(self._url_input)
        input_layout.addWidget(self._spinner)
        input_layout.addWidget(self._scan_btn)
        input_layout.addWidget(self._demo_btn)
        root.addWidget(input_frame)

        splitter = QSplitter(Qt.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        score_row = QHBoxLayout()
        self._gauge = ThreatScoreGauge()
        score_row.addWidget(self._gauge)

        verdict_col = QVBoxLayout()
        verdict_col.setSpacing(8)
        self._verdict_badge = VerdictBadge("UNKNOWN")
        verdict_col.addWidget(QLabel("VERDICT:"))
        verdict_col.addWidget(self._verdict_badge)
        self._final_url_label = QLabel("Final URL: —")
        self._final_url_label.setWordWrap(True)
        self._final_url_label.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        self._page_title_label = QLabel("Page: —")
        self._page_title_label.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        verdict_col.addWidget(self._final_url_label)
        verdict_col.addWidget(self._page_title_label)
        verdict_col.addStretch()
        score_row.addLayout(verdict_col)
        score_row.addStretch()
        left_layout.addLayout(score_row)

        stats_row = QHBoxLayout()
        self._stat_redirects  = StatCard("REDIRECTS",  "0", accent_color=p.accent_warn)
        self._stat_forms      = StatCard("FORMS",      "0", accent_color=p.accent_secondary)
        self._stat_scripts    = StatCard("SCRIPTS",    "0", accent_color=p.accent_tertiary)
        self._stat_exfil      = StatCard("EXFIL ENDPOINTS", "0", accent_color=p.accent_secondary)
        for card in (self._stat_redirects, self._stat_forms, self._stat_scripts, self._stat_exfil):
            stats_row.addWidget(card)
        left_layout.addLayout(stats_row)

        ind_label = QLabel("THREAT INDICATORS")
        ind_label.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 11px; font-weight: bold; letter-spacing: 2px;"
        )
        left_layout.addWidget(ind_label)

        ind_scroll = QScrollArea()
        ind_scroll.setWidgetResizable(True)
        ind_scroll.setStyleSheet("QScrollArea { border: 1px solid #1a1a1a; }")
        self._indicator_list = IndicatorListWidget()
        ind_scroll.setWidget(self._indicator_list)
        left_layout.addWidget(ind_scroll, 1)

        action_row = QHBoxLayout()
        self._export_btn = QPushButton("[ EXPORT HTML ]")
        self._export_btn.clicked.connect(self._export_html)
        self._export_btn.setEnabled(False)
        self._clear_btn = QPushButton("CLEAR")
        self._clear_btn.clicked.connect(self._clear)
        action_row.addWidget(self._export_btn)
        action_row.addWidget(self._clear_btn)
        action_row.addStretch()
        left_layout.addLayout(action_row)

        right_panel = QTabWidget()
        right_panel.setStyleSheet("QTabWidget { border: none; }")

        self._ssl_table = self._make_kv_table()
        self._dns_table = self._make_kv_table()
        self._forms_table = self._make_table(["Action", "Has Password", "Suspicious", "Reason"])
        self._scripts_table = self._make_table(["Patterns Matched", "Code Snippet"])
        self._exfil_table = self._make_table(["Type", "Destination", "Host"])
        self._log_widget = TerminalLogWidget()

        right_panel.addTab(self._wrap(self._ssl_table), "SSL/TLS")
        right_panel.addTab(self._wrap(self._dns_table), "DNS")
        right_panel.addTab(self._wrap(self._forms_table), "FORMS")
        right_panel.addTab(self._wrap(self._scripts_table), "SCRIPTS")
        right_panel.addTab(self._wrap(self._exfil_table), "EXFILTRATION")
        right_panel.addTab(self._log_widget, "SCAN LOG")

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([500, 500])
        root.addWidget(splitter, 1)

        self._log_widget.append_line("Phishing Scanner ready. Enter a URL and press [SCAN].", "INFO")

    def _load_demo(self) -> None:
        self._url_input.setText("http://paypa1-secure-login.tk/verify/account")
        self._log_widget.append_line("Demo URL loaded. Press [SCAN] to analyze.", "INFO")

    def _start_scan(self) -> None:
        url = self._url_input.text().strip()
        if not url:
            self._log_widget.append_line("Please enter a URL to scan.", "WARNING")
            return

        self._scan_btn.setEnabled(False)
        self._spinner.start()
        self._indicator_list.clear()
        self._log_widget.append_line(f"Starting analysis of: {url}", "SCAN")
        self._log_widget.append_line("Resolving DNS...", "INFO")
        self._log_widget.append_line("Checking SSL certificate...", "INFO")
        self._log_widget.append_line("Fetching page content...", "INFO")

        def worker() -> None:
            result = self._analyzer.analyze(url)
            self._signals.finished.emit(result)

        threading.Thread(target=worker, daemon=True).start()

    def _on_scan_done(self, result: URLAnalysisResult) -> None:
        self._spinner.stop()
        self._scan_btn.setEnabled(True)
        self._current_result = result

        self._gauge.set_score(result.threat_score)
        self._verdict_badge.set_verdict(result.verdict)
        self._final_url_label.setText(f"Final URL: {result.final_url or result.url}")
        self._page_title_label.setText(f"Page: {result.page_title or '—'}")

        self._stat_redirects.set_value(str(len(result.redirects)))
        self._stat_forms.set_value(str(len(result.form_actions)))
        self._stat_scripts.set_value(str(len(result.suspicious_scripts)))
        self._stat_exfil.set_value(str(len(result.exfiltration_endpoints)))

        self._indicator_list.set_indicators(result.indicators)

        ssl = result.ssl_info
        self._fill_kv_table(self._ssl_table, [
            ("Has HTTPS",   "Yes" if ssl.get("has_ssl") else "No"),
            ("Valid Cert",  "Yes" if ssl.get("valid") else f"No — {ssl.get('error','')}"),
            ("Subject CN",  ssl.get("subject_cn", "—")),
            ("Issuer",      ssl.get("issuer_org", "—")),
            ("Expires",     ssl.get("not_after", "—")),
            ("SAN",         ", ".join(ssl.get("san", []))),
        ])

        dns = result.dns_info
        geo = result.ip_geolocation
        self._fill_kv_table(self._dns_table, [
            ("Hostname",    dns.get("hostname", "—")),
            ("Resolved IP", dns.get("resolved_ip", "—")),
            ("DNS Status",  "OK" if dns.get("resolution_successful") else f"FAIL — {dns.get('error','')}"),
            ("Country",     geo.get("country", "—")),
            ("Region",      geo.get("region", "—")),
        ])

        self._forms_table.setRowCount(0)
        for form in result.form_actions:
            row = self._forms_table.rowCount()
            self._forms_table.insertRow(row)
            self._forms_table.setItem(row, 0, QTableWidgetItem(form.get("action", "—")))
            self._forms_table.setItem(row, 1, QTableWidgetItem("Yes" if form.get("has_password_field") else "No"))
            self._forms_table.setItem(row, 2, QTableWidgetItem("⚠ YES" if form.get("suspicious") else "No"))
            self._forms_table.setItem(row, 3, QTableWidgetItem(", ".join(form.get("reason", []))))

        self._scripts_table.setRowCount(0)
        for scr in result.suspicious_scripts:
            row = self._scripts_table.rowCount()
            self._scripts_table.insertRow(row)
            patterns = ", ".join(scr.get("patterns", []))
            self._scripts_table.setItem(row, 0, QTableWidgetItem(patterns))
            self._scripts_table.setItem(row, 1, QTableWidgetItem(scr.get("snippet", "")[:100]))

        self._exfil_table.setRowCount(0)
        for ep in result.exfiltration_endpoints:
            row = self._exfil_table.rowCount()
            self._exfil_table.insertRow(row)
            self._exfil_table.setItem(row, 0, QTableWidgetItem(ep.get("type", "—")))
            self._exfil_table.setItem(row, 1, QTableWidgetItem(ep.get("destination", "—")))
            self._exfil_table.setItem(row, 2, QTableWidgetItem(ep.get("host", "—")))

        verdict_msg = f"Analysis complete — Verdict: {result.verdict} | Score: {result.threat_score}/100"
        self._log_widget.append_line(verdict_msg, "CRITICAL" if result.threat_score > 60 else "INFO")
        if result.error:
            self._log_widget.append_line(f"Note: {result.error}", "WARNING")

        for ind in result.indicators:
            self._log_widget.append_line(ind, "WARNING")

        self._export_btn.setEnabled(True)
        db.save_scan("phishing_url", result.url, result.verdict, result.threat_score,
                     {"indicators": result.indicators[:10], "redirects": result.redirects})

    def _on_log(self, msg: str, level: str) -> None:
        self._log_widget.append_line(msg, level)

    def _export_html(self) -> None:
        if not self._current_result:
            return
        path = self._reporter.generate_html("phishing_url", self._current_result, "Phishing Website Scan")
        self._log_widget.append_line(f"HTML report saved: {path}", "INFO")

    def _clear(self) -> None:
        self._url_input.clear()
        self._gauge.set_score(0)
        self._verdict_badge.set_verdict("UNKNOWN")
        self._indicator_list.clear()
        self._log_widget.clear_log()
        self._current_result = None
        self._export_btn.setEnabled(False)
        for card in (self._stat_redirects, self._stat_forms, self._stat_scripts, self._stat_exfil):
            card.set_value("0")

    @staticmethod
    def _make_kv_table() -> QTableWidget:
        t = QTableWidget(0, 2)
        t.setHorizontalHeaderLabels(["Field", "Value"])
        t.horizontalHeader().setStretchLastSection(True)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        return t

    @staticmethod
    def _make_table(headers: list[str]) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setStretchLastSection(True)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        return t

    @staticmethod
    def _fill_kv_table(table: QTableWidget, rows: list[tuple]) -> None:
        table.setRowCount(0)
        for key, val in rows:
            r = table.rowCount()
            table.insertRow(r)
            table.setItem(r, 0, QTableWidgetItem(key))
            table.setItem(r, 1, QTableWidgetItem(str(val)))

    @staticmethod
    def _wrap(widget: QWidget) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 0)
        l.addWidget(widget)
        return w
