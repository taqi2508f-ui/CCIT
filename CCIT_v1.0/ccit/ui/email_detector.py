"""
CCIT Email Detector Page
UI for phishing email analysis: raw email input, header inspection, link/attachment scanning.
"""

import threading
from typing import Optional

from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPlainTextEdit,
                                QPushButton, QScrollArea, QSplitter,
                                QTabWidget, QTableWidget, QTableWidgetItem,
                                QVBoxLayout, QWidget, QFileDialog)

from modules.email_parser import EmailParser, EmailAnalysisResult
from modules.report_generator import ReportGenerator
from modules.database import db
from ui.theme import theme_manager
from ui.widgets import (IndicatorListWidget, ScanSpinner, StatCard,
                        TerminalLogWidget, ThreatScoreGauge, VerdictBadge)


DEMO_EMAIL = """From: "PayPal Security" <security@paypa1-confirm.com>
Reply-To: collect@evil-harvest.ru
To: victim@example.com
Subject: =?utf-8?b?VXJnZW50OiBWZXJpZnkgeW91ciBhY2NvdW50?=
Date: Mon, 05 Jan 2026 03:22:11 +0000
Message-ID: <phish-001@paypa1-confirm.com>
X-Mailer: PhishKit/3.2
Received: from [185.220.101.45] by mail.evil-harvest.ru

Dear Customer,

Your PayPal account has been suspended due to unusual activity.
Please click here to verify your account immediately:
http://paypa1-confirm.com/verify?token=abc123evil

Failure to verify within 24 hours will result in permanent suspension.

Regards,
PayPal Security Team
"""


class _Signals(QObject):
    finished = Signal(object)


class EmailDetectorPage(QWidget):
    """Email phishing detection page."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._parser = EmailParser()
        self._reporter = ReportGenerator()
        self._signals = _Signals()
        self._signals.finished.connect(self._on_done)
        self._current_result: Optional[EmailAnalysisResult] = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        p = theme_manager.palette
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        title = QLabel("[ ✉ ]  PHISHING EMAIL DETECTOR")
        title.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 16px; font-weight: bold; letter-spacing: 3px;"
        )
        sub = QLabel("Paste raw email (RFC 2822) or open an .eml file to analyze")
        sub.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        root.addWidget(title)
        root.addWidget(sub)

        btn_row = QHBoxLayout()
        self._scan_btn = QPushButton("[ ANALYZE ]")
        self._scan_btn.clicked.connect(self._start_scan)
        self._demo_btn = QPushButton("DEMO EMAIL")
        self._demo_btn.clicked.connect(self._load_demo)
        self._open_btn = QPushButton("OPEN .EML")
        self._open_btn.clicked.connect(self._open_file)
        self._export_btn = QPushButton("[ EXPORT HTML ]")
        self._export_btn.clicked.connect(self._export_html)
        self._export_btn.setEnabled(False)
        self._clear_btn = QPushButton("CLEAR")
        self._clear_btn.clicked.connect(self._clear)
        self._spinner = ScanSpinner(28)

        for w in (self._scan_btn, self._demo_btn, self._open_btn,
                  self._spinner, self._export_btn, self._clear_btn):
            btn_row.addWidget(w)
        btn_row.addStretch()
        root.addLayout(btn_row)

        splitter = QSplitter(Qt.Horizontal)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)

        input_label = QLabel("RAW EMAIL INPUT")
        input_label.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 10px; font-weight: bold; letter-spacing: 2px;"
        )
        ll.addWidget(input_label)
        self._email_input = QPlainTextEdit()
        self._email_input.setPlaceholderText("Paste raw RFC 2822 email here…")
        self._email_input.setStyleSheet(
            f"QPlainTextEdit {{ background: {p.surface}; border: 1px solid {p.border}; "
            f"font-size: 11px; padding: 8px; }}"
        )
        ll.addWidget(self._email_input, 1)

        score_row = QHBoxLayout()
        self._gauge = ThreatScoreGauge()
        score_row.addWidget(self._gauge)

        vc = QVBoxLayout()
        vc.setSpacing(6)
        self._verdict_badge = VerdictBadge("UNKNOWN")
        vc.addWidget(QLabel("VERDICT:"))
        vc.addWidget(self._verdict_badge)
        self._from_label = QLabel("From: —")
        self._from_label.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        self._subj_label = QLabel("Subject: —")
        self._subj_label.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        vc.addWidget(self._from_label)
        vc.addWidget(self._subj_label)
        vc.addStretch()
        score_row.addLayout(vc)
        score_row.addStretch()
        ll.addLayout(score_row)

        stats_row = QHBoxLayout()
        self._stat_links = StatCard("SUSPICIOUS LINKS", "0", accent_color=p.accent_secondary)
        self._stat_attach = StatCard("ATTACHMENTS",      "0", accent_color=p.accent_warn)
        self._stat_pixels = StatCard("TRACKING PIXELS",  "0", accent_color=p.accent_tertiary)
        for c in (self._stat_links, self._stat_attach, self._stat_pixels):
            stats_row.addWidget(c)
        ll.addLayout(stats_row)

        auth_row = QHBoxLayout()
        self._spf_label  = self._make_auth_label("SPF",   "?")
        self._dkim_label = self._make_auth_label("DKIM",  "?")
        self._dmarc_label = self._make_auth_label("DMARC","?")
        for w in (self._spf_label, self._dkim_label, self._dmarc_label):
            auth_row.addWidget(w)
        auth_row.addStretch()
        ll.addLayout(auth_row)

        ind_label = QLabel("THREAT INDICATORS")
        ind_label.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 10px; font-weight: bold; letter-spacing: 2px;"
        )
        ll.addWidget(ind_label)
        ind_scroll = QScrollArea()
        ind_scroll.setWidgetResizable(True)
        ind_scroll.setStyleSheet("QScrollArea { border: 1px solid #1a1a1a; }")
        self._indicator_list = IndicatorListWidget()
        ind_scroll.setWidget(self._indicator_list)
        ll.addWidget(ind_scroll, 1)

        right = QTabWidget()
        self._headers_table = self._make_kv()
        self._links_table   = self._make_table(["URL", "Suspicious", "Reasons"])
        self._attach_table  = self._make_table(["Filename", "Extension", "Risk", "SHA-256"])
        self._log_widget    = TerminalLogWidget()

        right.addTab(self._wrap(self._headers_table), "HEADERS")
        right.addTab(self._wrap(self._links_table), "LINKS")
        right.addTab(self._wrap(self._attach_table), "ATTACHMENTS")
        right.addTab(self._log_widget, "SCAN LOG")

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([500, 500])
        root.addWidget(splitter, 1)

        self._log_widget.append_line("Email Detector ready. Paste a raw email and press [ANALYZE].", "INFO")

    def _make_auth_label(self, name: str, status: str) -> QLabel:
        lbl = QLabel(f"{name}: {status}")
        lbl.setStyleSheet(
            "QLabel { background: #111; border: 1px solid #1a1a1a; "
            "padding: 4px 10px; font-size: 10px; color: #888; }"
        )
        return lbl

    def _update_auth_label(self, label: QLabel, name: str, status: str) -> None:
        color = "#00FF41" if status == "PASS" else ("#FF0055" if status in ("FAIL", "MISSING") else "#888")
        label.setText(f"{name}: {status}")
        label.setStyleSheet(
            f"QLabel {{ background: #111; border: 1px solid {color}; "
            f"color: {color}; padding: 4px 10px; font-size: 10px; font-weight: bold; }}"
        )

    def _load_demo(self) -> None:
        self._email_input.setPlainText(DEMO_EMAIL)
        self._log_widget.append_line("Demo phishing email loaded.", "INFO")

    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open Email File", "", "Email Files (*.eml *.msg *.txt);;All Files (*)")
        if path:
            try:
                with open(path, "r", errors="replace") as fh:
                    self._email_input.setPlainText(fh.read())
                self._log_widget.append_line(f"Loaded file: {path}", "INFO")
            except Exception as exc:
                self._log_widget.append_line(f"Error reading file: {exc}", "ERROR")

    def _start_scan(self) -> None:
        raw = self._email_input.toPlainText().strip()
        if not raw:
            self._log_widget.append_line("Please enter or load an email to analyze.", "WARNING")
            return
        self._scan_btn.setEnabled(False)
        self._spinner.start()
        self._log_widget.append_line("Analyzing email headers…", "SCAN")

        def worker() -> None:
            result = self._parser.analyze_raw(raw)
            self._signals.finished.emit(result)

        threading.Thread(target=worker, daemon=True).start()

    def _on_done(self, result: EmailAnalysisResult) -> None:
        self._spinner.stop()
        self._scan_btn.setEnabled(True)
        self._current_result = result

        self._gauge.set_score(result.threat_score)
        self._verdict_badge.set_verdict(result.verdict)
        self._from_label.setText(f"From: {result.sender_display} <{result.sender_email}>")
        self._subj_label.setText(f"Subject: {result.subject}")

        spf = result.spf_result
        dkim = result.dkim_result
        dmarc = result.dmarc_result
        self._update_auth_label(self._spf_label, "SPF",
            "PASS" if spf.get("pass") else ("FAIL" if spf.get("fail") else "NONE"))
        self._update_auth_label(self._dkim_label, "DKIM",
            "PASS" if dkim.get("pass") else ("FAIL" if dkim.get("fail") else "MISSING"))
        self._update_auth_label(self._dmarc_label, "DMARC",
            "PASS" if dmarc.get("pass") else ("FAIL" if dmarc.get("fail") else "NONE"))

        self._stat_links.set_value(str(len(result.suspicious_links)))
        self._stat_attach.set_value(str(len(result.attachments)))
        self._stat_pixels.set_value(str(len(result.tracking_pixels)))

        self._indicator_list.set_indicators(result.indicators)

        headers = result.headers
        self._fill_kv(self._headers_table, list(headers.items()))

        self._links_table.setRowCount(0)
        for lnk in result.suspicious_links:
            row = self._links_table.rowCount()
            self._links_table.insertRow(row)
            self._links_table.setItem(row, 0, QTableWidgetItem(lnk.get("url","")[:100]))
            self._links_table.setItem(row, 1, QTableWidgetItem("YES" if lnk.get("suspicious") else "NO"))
            self._links_table.setItem(row, 2, QTableWidgetItem(", ".join(lnk.get("reasons",[]))))

        self._attach_table.setRowCount(0)
        for att in result.attachments:
            row = self._attach_table.rowCount()
            self._attach_table.insertRow(row)
            self._attach_table.setItem(row, 0, QTableWidgetItem(att.get("filename","")))
            self._attach_table.setItem(row, 1, QTableWidgetItem(att.get("extension","")))
            self._attach_table.setItem(row, 2, QTableWidgetItem("⚠ DANGER" if att.get("dangerous_extension") else "OK"))
            self._attach_table.setItem(row, 3, QTableWidgetItem(att.get("sha256","")[:32]))

        level = "CRITICAL" if result.threat_score > 60 else "INFO"
        self._log_widget.append_line(
            f"Analysis complete — {result.verdict} | Score: {result.threat_score}/100", level
        )
        for ind in result.indicators:
            self._log_widget.append_line(ind, "WARNING")

        self._export_btn.setEnabled(True)
        db.save_scan("phishing_email", result.sender_email, result.verdict,
                     result.threat_score, {"subject": result.subject, "indicators": result.indicators[:8]})

    def _export_html(self) -> None:
        if not self._current_result:
            return
        path = self._reporter.generate_html("phishing_email", self._current_result, "Phishing Email Analysis")
        self._log_widget.append_line(f"HTML report saved: {path}", "INFO")

    def _clear(self) -> None:
        self._email_input.clear()
        self._gauge.set_score(0)
        self._verdict_badge.set_verdict("UNKNOWN")
        self._indicator_list.clear()
        self._log_widget.clear_log()
        self._current_result = None
        self._export_btn.setEnabled(False)

    @staticmethod
    def _make_kv() -> QTableWidget:
        t = QTableWidget(0, 2)
        t.setHorizontalHeaderLabels(["Header", "Value"])
        t.horizontalHeader().setStretchLastSection(True)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        return t

    @staticmethod
    def _fill_kv(table: QTableWidget, rows: list) -> None:
        table.setRowCount(0)
        for k, v in rows:
            r = table.rowCount()
            table.insertRow(r)
            table.setItem(r, 0, QTableWidgetItem(str(k)))
            table.setItem(r, 1, QTableWidgetItem(str(v)[:300]))

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
    def _wrap(w: QWidget) -> QWidget:
        c = QWidget()
        l = QVBoxLayout(c)
        l.setContentsMargins(0, 0, 0, 0)
        l.addWidget(w)
        return c
