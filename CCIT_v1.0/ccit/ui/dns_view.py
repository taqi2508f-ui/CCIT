"""
CCIT DNS Analyzer Page
UI for domain DNS analysis: A records, reverse DNS, SPF/DMARC, DGA detection, fast-flux.
"""

import threading
from typing import Optional

from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QLineEdit, QPushButton,
                                QScrollArea, QSplitter, QTabWidget,
                                QTableWidget, QTableWidgetItem, QVBoxLayout,
                                QWidget)

from modules.dns_analyzer import DNSAnalyzer, DNSAnalysisResult
from ui.theme import theme_manager
from ui.widgets import (IndicatorListWidget, ScanSpinner, StatCard,
                        TerminalLogWidget, ThreatScoreGauge, VerdictBadge)


class _Sig(QObject):
    done = Signal(object)


class DNSAnalyzerPage(QWidget):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._analyzer = DNSAnalyzer()
        self._signals = _Sig()
        self._signals.done.connect(self._on_done)
        self._setup_ui()

    def _setup_ui(self) -> None:
        p = theme_manager.palette
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        title = QLabel("[ ⊡ ]  DNS ANALYZER")
        title.setStyleSheet(f"color: {p.accent_primary}; font-size: 16px; font-weight: bold; letter-spacing: 3px;")
        sub = QLabel("Inspect DNS records — A, PTR, MX, NS, SPF, DMARC · DGA detection · fast-flux analysis")
        sub.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        root.addWidget(title)
        root.addWidget(sub)

        row = QHBoxLayout()
        lbl = QLabel("DOMAIN:")
        lbl.setStyleSheet(f"color: {p.accent_primary}; font-size: 11px; font-weight: bold; min-width: 70px;")
        self._input = QLineEdit()
        self._input.setPlaceholderText("example.com  or  paypa1-confirm.ru")
        self._input.returnPressed.connect(self._scan)
        self._scan_btn = QPushButton("[ ANALYZE ]")
        self._scan_btn.setFixedWidth(110)
        self._scan_btn.clicked.connect(self._scan)
        self._demo_btn = QPushButton("DEMO")
        self._demo_btn.setFixedWidth(70)
        self._demo_btn.clicked.connect(lambda: (self._input.setText("paypa1-confirm.ru"), self._scan()))
        self._spinner = ScanSpinner(28)
        row.addWidget(lbl)
        row.addWidget(self._input)
        row.addWidget(self._spinner)
        row.addWidget(self._scan_btn)
        row.addWidget(self._demo_btn)
        root.addLayout(row)

        splitter = QSplitter(Qt.Horizontal)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(10)

        sr = QHBoxLayout()
        self._gauge = ThreatScoreGauge()
        sr.addWidget(self._gauge)
        vc = QVBoxLayout()
        self._verdict_badge = VerdictBadge("UNKNOWN")
        self._tld_label = QLabel("TLD: —")
        self._tld_label.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        self._ips_label = QLabel("Resolved IPs: —")
        self._ips_label.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        vc.addWidget(QLabel("VERDICT:"))
        vc.addWidget(self._verdict_badge)
        vc.addWidget(self._tld_label)
        vc.addWidget(self._ips_label)
        vc.addStretch()
        sr.addLayout(vc)
        sr.addStretch()
        ll.addLayout(sr)

        stats = QHBoxLayout()
        self._stat_ips   = StatCard("RESOLVED IPs",    "0", accent_color=p.accent_primary)
        self._stat_dga   = StatCard("DGA SCORE",       "—", accent_color=p.accent_secondary)
        self._stat_flux  = StatCard("FAST-FLUX",       "NO", accent_color=p.accent_warn)
        for c in (self._stat_ips, self._stat_dga, self._stat_flux):
            stats.addWidget(c)
        ll.addLayout(stats)

        il = QLabel("INDICATORS")
        il.setStyleSheet(f"color: {p.accent_primary}; font-size: 10px; font-weight: bold; letter-spacing: 2px;")
        ll.addWidget(il)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self._ind_list = IndicatorListWidget()
        scroll.setWidget(self._ind_list)
        ll.addWidget(scroll, 1)

        right = QTabWidget()
        self._dns_table  = self._mkt(["Field", "Value"])
        self._rev_table  = self._mkt(["IP", "Reverse DNS"])
        self._log        = TerminalLogWidget()
        right.addTab(self._wrap(self._dns_table), "DNS RECORDS")
        right.addTab(self._wrap(self._rev_table), "REVERSE DNS")
        right.addTab(self._log, "LOG")

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([450, 550])
        root.addWidget(splitter, 1)
        self._log.append_line("DNS Analyzer ready.", "INFO")

    def _scan(self) -> None:
        domain = self._input.text().strip()
        if not domain:
            return
        self._scan_btn.setEnabled(False)
        self._spinner.start()
        self._log.append_line(f"Analyzing DNS for: {domain}", "SCAN")

        def worker() -> None:
            result = self._analyzer.analyze(domain)
            self._signals.done.emit(result)

        threading.Thread(target=worker, daemon=True).start()

    def _on_done(self, result: DNSAnalysisResult) -> None:
        self._spinner.stop()
        self._scan_btn.setEnabled(True)
        self._gauge.set_score(result.threat_score)
        self._verdict_badge.set_verdict(result.verdict)
        self._tld_label.setText(f"TLD: {result.tld}")
        self._ips_label.setText(f"Resolved IPs: {', '.join(result.resolved_ips) or 'None'}")
        self._stat_ips.set_value(str(result.ip_count))
        self._stat_dga.set_value(f"{result.dga_score:.0f}")
        self._stat_flux.set_value("YES" if result.fast_flux else "NO")
        if result.fast_flux:
            self._stat_flux.set_accent("#FF0055")
        self._ind_list.set_indicators(result.indicators)

        self._fill(self._dns_table, [
            ("Domain",    result.domain),
            ("TLD",       result.tld),
            ("IP Count",  str(result.ip_count)),
            ("IPs",       ", ".join(result.resolved_ips)),
            ("DGA Score", f"{result.dga_score}/100"),
            ("Is DGA",    "Yes" if result.is_dga else "No"),
            ("Fast Flux", "Yes" if result.fast_flux else "No"),
            ("Entropy",   str(result.domain_entropy)),
            ("SPF",       result.spf_record or "Not found"),
            ("DMARC",     result.dmarc_record or "Not found"),
        ])
        self._rev_table.setRowCount(0)
        for ip, hostname in result.reverse_dns.items():
            r = self._rev_table.rowCount()
            self._rev_table.insertRow(r)
            self._rev_table.setItem(r, 0, QTableWidgetItem(ip))
            self._rev_table.setItem(r, 1, QTableWidgetItem(hostname))

        self._log.append_line(f"Done — {result.verdict} | Score: {result.threat_score}/100", "INFO")
        for ind in result.indicators:
            self._log.append_line(ind, "WARNING")

    @staticmethod
    def _mkt(headers: list) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setStretchLastSection(True)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        return t

    @staticmethod
    def _fill(table: QTableWidget, rows: list) -> None:
        table.setRowCount(0)
        for k, v in rows:
            r = table.rowCount()
            table.insertRow(r)
            table.setItem(r, 0, QTableWidgetItem(str(k)))
            table.setItem(r, 1, QTableWidgetItem(str(v)))

    @staticmethod
    def _wrap(w: QWidget) -> QWidget:
        c = QWidget()
        l = QVBoxLayout(c)
        l.setContentsMargins(0, 0, 0, 0)
        l.addWidget(w)
        return c
