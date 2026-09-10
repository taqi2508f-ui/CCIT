"""
CCIT Network Monitor Dashboard
Real-time traffic charts, connection table, suspicious IP alerts, and packet stats.
"""

from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton,
                                QScrollArea, QSplitter, QTableWidget,
                                QTableWidgetItem, QVBoxLayout, QWidget)

from modules.network_monitor import NetworkMonitor, NetworkSnapshot
from modules.traffic_monitor import TrafficMonitor, TrafficPoint
from modules.packet_inspector import PacketInspector
from ui.theme import theme_manager
from ui.widgets import StatCard, TerminalLogWidget, TrafficChart


class NetworkDashboardPage(QWidget):
    """Real-time network monitoring dashboard."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._net_monitor = NetworkMonitor(poll_interval=2.0)
        self._traffic_monitor = TrafficMonitor(sample_interval=1.0)
        self._inspector = PacketInspector()
        self._monitoring = False
        self._demo_packets = self._inspector.generate_demo_packets()
        self._setup_ui()
        self._net_monitor.register_callback(self._on_network_snapshot)
        self._traffic_monitor.register_callback(self._on_traffic_point)

    def _setup_ui(self) -> None:
        p = theme_manager.palette
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        header_row = QHBoxLayout()
        title = QLabel("[ ◉ ]  REAL-TIME NETWORK MONITOR")
        title.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 16px; font-weight: bold; letter-spacing: 3px;"
        )
        self._status_label = QLabel("● STOPPED")
        self._status_label.setStyleSheet(f"color: {p.text_secondary}; font-size: 11px;")
        self._toggle_btn = QPushButton("[ START MONITORING ]")
        self._toggle_btn.setFixedWidth(180)
        self._toggle_btn.clicked.connect(self._toggle_monitoring)
        header_row.addWidget(title)
        header_row.addStretch()
        header_row.addWidget(self._status_label)
        header_row.addWidget(self._toggle_btn)
        root.addLayout(header_row)

        sub = QLabel("Live connections · suspicious IPs · bandwidth graphs · packet stats")
        sub.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px;")
        root.addWidget(sub)

        stats_row = QHBoxLayout()
        self._stat_total     = StatCard("TOTAL CONNECTIONS", "0", accent_color=p.accent_primary)
        self._stat_estab     = StatCard("ESTABLISHED",       "0", accent_color=p.accent_tertiary)
        self._stat_listen    = StatCard("LISTENING",         "0", accent_color=p.accent_warn)
        self._stat_suspicious = StatCard("SUSPICIOUS",       "0", accent_color=p.accent_secondary)
        self._stat_tx        = StatCard("TX RATE",           "0 KB/s", accent_color=p.accent_primary)
        self._stat_rx        = StatCard("RX RATE",           "0 KB/s", accent_color=p.accent_tertiary)
        for c in (self._stat_total, self._stat_estab, self._stat_listen,
                  self._stat_suspicious, self._stat_tx, self._stat_rx):
            stats_row.addWidget(c)
        root.addLayout(stats_row)

        splitter = QSplitter(Qt.Vertical)

        charts_widget = QWidget()
        charts_layout = QHBoxLayout(charts_widget)
        charts_layout.setContentsMargins(0, 0, 0, 0)
        charts_layout.setSpacing(10)

        self._bw_chart = TrafficChart("BANDWIDTH (KB/s)", p.chart_line_1, p.chart_line_2)
        self._bw_chart.set_labels("TX", "RX")
        self._bw_chart.setMinimumHeight(150)

        self._conn_chart = TrafficChart("CONNECTIONS", p.chart_line_3, p.chart_line_4)
        self._conn_chart.set_labels("TOTAL", "SUSPICIOUS")
        self._conn_chart.setMinimumHeight(150)

        charts_layout.addWidget(self._bw_chart, 3)
        charts_layout.addWidget(self._conn_chart, 2)
        splitter.addWidget(charts_widget)

        bottom = QWidget()
        bottom_layout = QHBoxLayout(bottom)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(10)

        conn_panel = QWidget()
        conn_l = QVBoxLayout(conn_panel)
        conn_l.setContentsMargins(0, 0, 0, 0)
        conn_label = QLabel("ACTIVE CONNECTIONS")
        conn_label.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 10px; font-weight: bold; letter-spacing: 2px;"
        )
        conn_l.addWidget(conn_label)
        self._conn_table = QTableWidget(0, 7)
        self._conn_table.setHorizontalHeaderLabels(
            ["Local", "Remote", "Port", "Protocol", "Status", "Process", "⚠"]
        )
        self._conn_table.horizontalHeader().setStretchLastSection(True)
        self._conn_table.verticalHeader().setVisible(False)
        self._conn_table.setAlternatingRowColors(True)
        self._conn_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._conn_table.setSelectionBehavior(QTableWidget.SelectRows)
        conn_l.addWidget(self._conn_table)

        log_panel = QWidget()
        log_l = QVBoxLayout(log_panel)
        log_l.setContentsMargins(0, 0, 0, 0)
        log_label = QLabel("THREAT LOG")
        log_label.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 10px; font-weight: bold; letter-spacing: 2px;"
        )
        log_l.addWidget(log_label)
        self._log_widget = TerminalLogWidget()
        log_l.addWidget(self._log_widget)

        bottom_layout.addWidget(conn_panel, 3)
        bottom_layout.addWidget(log_panel, 2)
        splitter.addWidget(bottom)

        splitter.setSizes([260, 340])
        root.addWidget(splitter, 1)

        self._log_widget.append_line("Network monitor initialized. Press [START MONITORING] to begin.", "INFO")
        self._load_demo_connections()

    def _load_demo_connections(self) -> None:
        self._conn_table.setRowCount(0)
        for pkt in self._demo_packets:
            self._add_connection_row(
                local=pkt["src"],
                remote=pkt["dst"],
                port=pkt["port"],
                protocol=pkt["protocol"],
                status=pkt["status"],
                process="demo",
                suspicious=pkt["suspicious"],
                note=pkt["note"],
            )
        self._stat_total.set_value(str(len(self._demo_packets)))
        self._stat_suspicious.set_value(str(sum(1 for p in self._demo_packets if p["suspicious"])))

    def _toggle_monitoring(self) -> None:
        if not self._monitoring:
            self._monitoring = True
            self._net_monitor.start()
            self._traffic_monitor.start()
            self._toggle_btn.setText("[ STOP MONITORING ]")
            self._status_label.setText("● MONITORING ACTIVE")
            self._status_label.setStyleSheet("color: #00FF41; font-size: 11px; font-weight: bold;")
            self._log_widget.append_line("Network monitoring started.", "INFO")
        else:
            self._monitoring = False
            self._net_monitor.stop()
            self._traffic_monitor.stop()
            self._toggle_btn.setText("[ START MONITORING ]")
            self._status_label.setText("● STOPPED")
            self._status_label.setStyleSheet(f"color: {theme_manager.palette.text_secondary}; font-size: 11px;")
            self._log_widget.append_line("Network monitoring stopped.", "INFO")

    def _on_network_snapshot(self, snap: NetworkSnapshot) -> None:
        self._stat_total.set_value(str(snap.total_connections))
        self._stat_estab.set_value(str(snap.established))
        self._stat_listen.set_value(str(snap.listening))
        if snap.suspicious_count > 0:
            self._stat_suspicious.set_value(str(snap.suspicious_count))
            self._stat_suspicious.set_accent("#FF0055")
        else:
            self._stat_suspicious.set_value("0")
            self._stat_suspicious.set_accent(theme_manager.palette.accent_secondary)

        self._conn_table.setRowCount(0)
        for conn in snap.connections[:100]:
            self._add_connection_row(
                local=f"{conn.local_addr}:{conn.local_port}",
                remote=f"{conn.remote_addr}:{conn.remote_port}" if conn.remote_addr else "—",
                port=conn.remote_port,
                protocol=conn.protocol,
                status=conn.status,
                process=conn.process_name,
                suspicious=conn.suspicious,
                note="; ".join(conn.risk_reasons),
            )

        self._conn_chart.push(float(snap.total_connections), float(snap.suspicious_count))

        if snap.suspicious_count > 0:
            self._log_widget.append_line(
                f"⚠ {snap.suspicious_count} suspicious connection(s) detected", "WARNING"
            )
            for conn in snap.connections:
                if conn.suspicious:
                    self._log_widget.append_line(
                        f"SUSPICIOUS: {conn.local_addr}:{conn.local_port} → "
                        f"{conn.remote_addr}:{conn.remote_port} [{conn.process_name}]",
                        "ERROR",
                    )

    def _on_traffic_point(self, point: TrafficPoint) -> None:
        self._stat_tx.set_value(f"{point.sent_rate_kbps:.1f} KB/s")
        self._stat_rx.set_value(f"{point.recv_rate_kbps:.1f} KB/s")
        self._bw_chart.push(point.sent_rate_kbps, point.recv_rate_kbps)

    def _add_connection_row(
        self,
        local: str,
        remote: str,
        port: int,
        protocol: str,
        status: str,
        process: str,
        suspicious: bool,
        note: str = "",
    ) -> None:
        row = self._conn_table.rowCount()
        self._conn_table.insertRow(row)
        items = [
            QTableWidgetItem(local),
            QTableWidgetItem(remote),
            QTableWidgetItem(str(port)),
            QTableWidgetItem(protocol),
            QTableWidgetItem(status),
            QTableWidgetItem(process),
            QTableWidgetItem("⚠" if suspicious else ""),
        ]
        for col, item in enumerate(items):
            if suspicious:
                item.setForeground(Qt.red)
            self._conn_table.setItem(row, col, item)

    def cleanup(self) -> None:
        if self._monitoring:
            self._net_monitor.stop()
            self._traffic_monitor.stop()
