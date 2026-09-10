"""
CCIT Main Window — v2 Cyberpunk Ultra Edition
Matrix rain loading screen, animated page transitions, scanline overlays,
glitch title, pulsing status bar.
"""

from __future__ import annotations

import json
import math
import os
import random
import sys
from typing import Optional

from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPen, QBrush
from PySide6.QtWidgets import (QGraphicsOpacityEffect, QHBoxLayout, QLabel,
                                QMainWindow, QStackedWidget, QVBoxLayout,
                                QWidget)

from modules.database import db
from modules.logger import logger
from ui.sidebar import Sidebar
from ui.theme import theme_manager
from ui.widgets import MatrixRainWidget, ScanlineOverlay, StatCard, GlitchLabel


# ══════════════════════════════════════════════════════════════════════════════
#  Matrix Rain Loading Screen
# ══════════════════════════════════════════════════════════════════════════════

BOOT_MESSAGES = [
    "INITIALIZING CORE SUBSYSTEMS...",
    "LOADING THREAT SIGNATURE DATABASE...",
    "WARMING UP URL ANALYSIS ENGINE...",
    "INITIALIZING EMAIL PARSER MODULE...",
    "LOADING STATIC BINARY ANALYZER...",
    "STARTING NETWORK MONITOR...",
    "CONNECTING TO LOCAL DATABASE...",
    "LOADING DNS ANALYSIS ENGINE...",
    "CALIBRATING ENTROPY DETECTOR...",
    "VERIFYING MODULE INTEGRITY...",
    "ALL SYSTEMS NOMINAL.",
    "LAUNCHING CCIT...",
]


class CyberProgressBar(QWidget):
    """Animated segmented cyberpunk progress bar."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._progress = 0.0
        self.setFixedHeight(14)

    def set_progress(self, value: float) -> None:
        self._progress = max(0.0, min(1.0, value))
        self.update()

    def paintEvent(self, event) -> None:
        w, h = self.width(), self.height()
        p = theme_manager.palette
        acc = QColor(p.accent_primary)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Background
        painter.fillRect(self.rect(), QColor(p.border))

        # Filled portion
        fill_w = int(w * self._progress)
        if fill_w > 0:
            grad = QLinearGradient(0, 0, fill_w, 0)
            grad.setColorAt(0.0, QColor(p.accent_tertiary))
            grad.setColorAt(0.5, acc)
            grad.setColorAt(1.0, QColor(p.text_primary))
            painter.fillRect(0, 0, fill_w, h, QBrush(grad))

            # Glow
            glow_c = QColor(acc)
            glow_c.setAlpha(80)
            painter.fillRect(fill_w - 12, 0, 12, h, glow_c)

        # Segment separators
        seg_size = max(4, w // 40)
        painter.setPen(QPen(QColor(0, 0, 0, 120), 1))
        for i in range(1, 40):
            x = i * seg_size
            painter.drawLine(x, 0, x, h)

        # Border
        painter.setPen(QPen(acc, 1))
        painter.drawRect(0, 0, w - 1, h - 1)

        painter.end()


class LoadingScreen(QWidget):
    """Full-screen matrix rain loading overlay with boot sequence."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("loading_screen")
        self._msg_index = 0
        self._done = False
        self._setup_ui()
        self._start_sequence()

    def _setup_ui(self) -> None:
        p = theme_manager.palette

        # Matrix rain background
        self._rain = MatrixRainWidget(self, color=p.accent_primary, density=0.9)
        self._rain.setGeometry(self.rect())

        # Scanline overlay
        self._scanline = ScanlineOverlay(self, alpha=25, spacing=2)
        self._scanline.setGeometry(self.rect())

        # Dark center overlay
        self._center = QWidget(self)
        self._center.setStyleSheet("background: transparent;")

        center_layout = QVBoxLayout(self._center)
        center_layout.setAlignment(Qt.AlignCenter)
        center_layout.setSpacing(16)

        # Logo
        self._logo_label = GlitchLabel("◈ CCIT", glitch_interval=1800,
                                       color=p.accent_primary)
        self._logo_label.setAlignment(Qt.AlignCenter)
        self._logo_label.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 52px; font-weight: bold;"
            f"letter-spacing: 14px; font-family: 'Courier New';"
        )

        subtitle = QLabel("CYBER CRIME INVESTIGATION TOOL")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(
            f"color: {p.text_secondary}; font-size: 13px; letter-spacing: 5px;"
            f"font-family: 'Courier New';"
        )

        ver = QLabel("v1.0.0  ·  PROFESSIONAL EDITION  ·  OFFLINE MODE")
        ver.setAlignment(Qt.AlignCenter)
        ver.setStyleSheet(
            f"color: {p.text_disabled}; font-size: 9px; letter-spacing: 3px;"
            f"font-family: 'Courier New';"
        )

        # Divider line
        div = QWidget()
        div.setFixedHeight(1)
        div.setStyleSheet(f"background: {p.accent_primary};")

        # Boot message
        self._msg_label = QLabel(BOOT_MESSAGES[0])
        self._msg_label.setAlignment(Qt.AlignCenter)
        self._msg_label.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 11px; letter-spacing: 2px;"
            f"font-family: 'Courier New'; min-height: 20px;"
        )

        # Progress bar
        self._progress = CyberProgressBar()
        self._progress.setFixedWidth(480)
        prog_row = QHBoxLayout()
        prog_row.addStretch()
        prog_row.addWidget(self._progress)
        prog_row.addStretch()

        # Percentage label
        self._pct_label = QLabel("0%")
        self._pct_label.setAlignment(Qt.AlignCenter)
        self._pct_label.setStyleSheet(
            f"color: {p.text_secondary}; font-size: 10px; font-family: 'Courier New';"
        )

        # Bottom disclaimer
        disclaimer = QLabel(
            "[ AUTHORIZED DEFENSIVE SECURITY USE ONLY  ·  DO NOT USE FOR UNAUTHORIZED ACCESS ]"
        )
        disclaimer.setAlignment(Qt.AlignCenter)
        disclaimer.setStyleSheet(
            f"color: {p.text_disabled}; font-size: 8px; letter-spacing: 2px;"
            f"font-family: 'Courier New';"
        )

        center_layout.addStretch(2)
        center_layout.addWidget(self._logo_label)
        center_layout.addWidget(subtitle)
        center_layout.addWidget(ver)
        center_layout.addSpacing(20)
        center_layout.addWidget(div)
        center_layout.addSpacing(16)
        center_layout.addWidget(self._msg_label)
        center_layout.addSpacing(8)
        center_layout.addLayout(prog_row)
        center_layout.addWidget(self._pct_label)
        center_layout.addStretch(2)
        center_layout.addWidget(disclaimer)
        center_layout.addSpacing(20)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._rain.setGeometry(self.rect())
        self._scanline.setGeometry(self.rect())
        self._center.setGeometry(self.rect())

    def _start_sequence(self) -> None:
        self._seq_timer = QTimer(self)
        self._seq_timer.setInterval(280)
        self._seq_timer.timeout.connect(self._next_message)
        self._seq_timer.start()

    def _next_message(self) -> None:
        self._msg_index += 1
        if self._msg_index >= len(BOOT_MESSAGES):
            self._seq_timer.stop()
            self._done = True
            return
        msg = BOOT_MESSAGES[self._msg_index]
        self._msg_label.setText(msg)
        progress = self._msg_index / (len(BOOT_MESSAGES) - 1)
        self._progress.set_progress(progress)
        self._pct_label.setText(f"{int(progress * 100)}%")

    def is_done(self) -> bool:
        return self._done

    def total_ms(self) -> int:
        return len(BOOT_MESSAGES) * 280 + 400

    def fade_out(self, callback) -> None:
        effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(effect)
        self._fade_anim = QPropertyAnimation(effect, b"opacity")
        self._fade_anim.setDuration(600)
        self._fade_anim.setStartValue(1.0)
        self._fade_anim.setEndValue(0.0)
        self._fade_anim.setEasingCurve(QEasingCurve.OutCubic)
        self._fade_anim.finished.connect(callback)
        self._fade_anim.start()


# ══════════════════════════════════════════════════════════════════════════════
#  Dashboard Page
# ══════════════════════════════════════════════════════════════════════════════

class DashboardPage(QWidget):
    """Main dashboard — stats overview, module status, quick start guide."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._setup_ui()
        QTimer.singleShot(200, self._refresh_stats)

    def _setup_ui(self) -> None:
        p = theme_manager.palette
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 18)
        root.setSpacing(16)

        # Title row
        title_widget = QWidget()
        title_widget.setStyleSheet(
            f"background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 {p.surface_2},stop:0.6 {p.surface},stop:1 {p.background});"
            f"border: 1px solid {p.border}; border-left: 4px solid {p.accent_primary};"
            f"padding: 10px 14px;"
        )
        title_h = QHBoxLayout(title_widget)
        title_h.setContentsMargins(14, 10, 14, 10)

        title_glitch = GlitchLabel("[ ⊞ ]  DASHBOARD", glitch_interval=5000,
                                   color=p.accent_primary)
        title_glitch.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 16px; font-weight: bold;"
            f"letter-spacing: 3px; font-family: 'Courier New'; background: transparent;"
        )
        sub = QLabel("System overview  ·  Threat statistics  ·  Module status")
        sub.setStyleSheet(f"color: {p.text_secondary}; font-size: 10px; background: transparent;")

        title_h.addWidget(title_glitch)
        title_h.addStretch()
        title_h.addWidget(sub)
        root.addWidget(title_widget)

        # Stats row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(10)
        self._stat_scans    = StatCard("TOTAL SCANS",      "0", accent_color=p.accent_primary)
        self._stat_threats  = StatCard("THREATS DETECTED", "0", accent_color=p.accent_secondary)
        self._stat_net      = StatCard("NETWORK EVENTS",   "0", accent_color=p.accent_tertiary)
        self._stat_susp_net = StatCard("SUSPICIOUS CONNS", "0", accent_color=p.accent_warn)
        for c in (self._stat_scans, self._stat_threats, self._stat_net, self._stat_susp_net):
            stats_row.addWidget(c)
        root.addLayout(stats_row)

        # Module status grid
        mod_lbl = QLabel("MODULE STATUS")
        mod_lbl.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 10px; font-weight: bold; letter-spacing: 3px;"
        )
        root.addWidget(mod_lbl)

        mods_row = QHBoxLayout()
        mods_row.setSpacing(8)
        modules = [
            ("URL ANALYZER",     "READY", p.accent_primary),
            ("EMAIL PARSER",     "READY", p.accent_primary),
            ("FILE MONITOR",     "READY", p.accent_primary),
            ("NET MONITOR",      "READY", p.accent_primary),
            ("DNS ANALYZER",     "READY", p.accent_primary),
            ("SIG MATCHER",      "READY", p.accent_primary),
            ("REPORT GEN",       "READY", p.accent_primary),
            ("DATABASE",         "READY", p.accent_primary),
        ]
        for mod_name, status, color in modules:
            card = StatCard(mod_name, "✔ " + status, accent_color=color)
            card.setFixedHeight(72)
            mods_row.addWidget(card)
        root.addLayout(mods_row)

        # Quick guide
        guide_lbl = QLabel("QUICK START GUIDE")
        guide_lbl.setStyleSheet(
            f"color: {p.accent_primary}; font-size: 10px; font-weight: bold; letter-spacing: 3px;"
        )
        root.addWidget(guide_lbl)

        guide_items = [
            ("⛓", "PHISHING SCANNER",   p.accent_primary,
             "Enter any URL → detect fake SSL, hidden forms, data exfiltration, redirect chains"),
            ("✉", "EMAIL DETECTOR",     p.accent_tertiary,
             "Paste raw .eml email → detect header spoofing, malicious links, dangerous attachments"),
            ("☣", "MALWARE ANALYZER",   p.accent_secondary,
             "Select any file → entropy analysis, PE inspection, ransomware/keylogger/spyware flags"),
            ("◉", "NETWORK MONITOR",    p.accent_warn,
             "Start monitor → live connections, bandwidth charts, suspicious IP real-time alerts"),
            ("▤", "REPORTS",            p.accent_purple if hasattr(p, 'accent_purple') else "#BF00FF",
             "Browse full scan history, open generated reports, export JSON/HTML findings"),
        ]
        for icon, name, color, desc in guide_items:
            item = self._make_guide_item(icon, name, color, desc)
            root.addWidget(item)

        root.addStretch(1)

        disclaimer = QLabel(
            "◈  CCIT is designed exclusively for ETHICAL DEFENSIVE cybersecurity investigation. "
            "Do not use for unauthorized access, offensive operations, or any illegal purpose."
        )
        disclaimer.setStyleSheet(
            f"color: {p.text_disabled}; font-size: 9px; font-family: 'Courier New';"
        )
        disclaimer.setWordWrap(True)
        root.addWidget(disclaimer)

    def _make_guide_item(self, icon: str, name: str, color: str, desc: str) -> QWidget:
        p = theme_manager.palette
        frame = QWidget()
        frame.setStyleSheet(
            f"QWidget {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 {p.surface_2},stop:1 {p.surface});"
            f"border: 1px solid {p.border}; border-left: 3px solid {color}; }}"
            f"QWidget:hover {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 {p.surface_3},stop:1 {p.surface_2});"
            f"border-left: 3px solid {color}; }}"
        )
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(10, 8, 12, 8)
        layout.setSpacing(12)

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(
            f"color: {color}; font-size: 18px; min-width: 26px; background: transparent;"
        )
        icon_lbl.setFixedWidth(26)

        name_lbl = QLabel(name)
        name_lbl.setStyleSheet(
            f"color: {color}; font-size: 10px; font-weight: bold; letter-spacing: 1px;"
            f"min-width: 160px; background: transparent;"
        )

        desc_lbl = QLabel(desc)
        desc_lbl.setStyleSheet(
            f"color: {p.text_secondary}; font-size: 10px; background: transparent;"
        )
        desc_lbl.setWordWrap(True)

        layout.addWidget(icon_lbl)
        layout.addWidget(name_lbl)
        layout.addWidget(desc_lbl, 1)
        return frame

    def _refresh_stats(self) -> None:
        try:
            stats = db.get_stats()
            self._stat_scans.set_value(str(stats.get("total_scans", 0)))
            self._stat_threats.set_value(str(stats.get("threats_found", 0)))
            self._stat_net.set_value(str(stats.get("network_events", 0)))
            self._stat_susp_net.set_value(str(stats.get("suspicious_connections", 0)))
        except Exception:
            pass

    def refresh(self) -> None:
        self._refresh_stats()


# ══════════════════════════════════════════════════════════════════════════════
#  Animated Stacked Widget (fade transitions)
# ══════════════════════════════════════════════════════════════════════════════

class FadingStack(QStackedWidget):
    """QStackedWidget with opacity fade between pages."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._effect: Optional[QGraphicsOpacityEffect] = None
        self._anim: Optional[QPropertyAnimation] = None

    def switch_to(self, widget: QWidget) -> None:
        if self.currentWidget() is widget:
            return
        # Fade out
        effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity")
        anim.setDuration(120)
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim = anim

        def do_switch() -> None:
            self.setCurrentWidget(widget)
            anim2 = QPropertyAnimation(effect, b"opacity")
            anim2.setDuration(200)
            anim2.setStartValue(0.0)
            anim2.setEndValue(1.0)
            anim2.setEasingCurve(QEasingCurve.InCubic)
            anim2.finished.connect(lambda: self.setGraphicsEffect(None))
            self._anim = anim2
            anim2.start()

        anim.finished.connect(do_switch)
        anim.start()


# ══════════════════════════════════════════════════════════════════════════════
#  Animated Status Bar
# ══════════════════════════════════════════════════════════════════════════════

class CyberStatusBar(QWidget):
    """Custom animated status bar at the bottom of the window."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(28)
        self._pulse = 0.0
        self._pulse_dir = 1.0
        self._left_text = "◈ CCIT v1.0.0  ·  Offline Mode  ·  All Modules Ready"
        self._right_text = ""

        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

        self._clock_timer = QTimer(self)
        self._clock_timer.setInterval(1000)
        self._clock_timer.timeout.connect(self._update_clock)
        self._clock_timer.start()
        self._update_clock()

    def _tick(self) -> None:
        self._pulse += self._pulse_dir * 0.04
        self._pulse = max(0.0, min(1.0, self._pulse))
        if self._pulse >= 1.0: self._pulse_dir = -1.0
        elif self._pulse <= 0.0: self._pulse_dir = 1.0
        self.update()

    def _update_clock(self) -> None:
        from datetime import datetime
        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self._right_text = f"{now}  ·  DEFENSIVE USE ONLY"
        self.update()

    def paintEvent(self, event) -> None:
        w, h = self.width(), self.height()
        p = theme_manager.palette
        acc = QColor(p.accent_primary)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, False)

        # Background
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, QColor(p.surface_2))
        grad.setColorAt(1, QColor(p.surface))
        painter.fillRect(self.rect(), QBrush(grad))

        # Top border glow
        top_c = QColor(acc)
        top_c.setAlpha(int(100 + self._pulse * 80))
        painter.fillRect(0, 0, w, 1, top_c)

        # Left text
        painter.setPen(QPen(QColor(p.text_secondary)))
        painter.setFont(QFont("Courier New", 9))
        painter.drawText(10, 0, w // 2, h, Qt.AlignVCenter | Qt.AlignLeft, self._left_text)

        # Right text
        painter.setPen(QPen(QColor(p.text_disabled)))
        painter.drawText(w // 2, 0, w // 2 - 10, h,
                         Qt.AlignVCenter | Qt.AlignRight, self._right_text)

        # Segment decorations
        painter.setPen(QPen(QColor(p.border), 1))
        for offset in [w // 3, 2 * w // 3]:
            painter.drawLine(offset, 4, offset, h - 4)

        painter.end()


# ══════════════════════════════════════════════════════════════════════════════
#  Main Window
# ══════════════════════════════════════════════════════════════════════════════

class CCITMainWindow(QMainWindow):
    """Root application window — matrix loading, animated nav, fading pages."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("CCIT — Cyber Crime Investigation Tool v1.0.0")
        self.setMinimumSize(1200, 750)
        self.resize(1440, 900)
        self.setStyleSheet(theme_manager.stylesheet())

        self._pages: dict[str, QWidget] = {}
        self._loading_screen: Optional[LoadingScreen] = None

        self._setup_ui()
        self._show_loading()

    def _setup_ui(self) -> None:
        # Remove default status bar and replace with custom
        self.statusBar().hide()

        central = QWidget()
        self.setCentralWidget(central)

        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Main content row
        content_row = QHBoxLayout()
        content_row.setContentsMargins(0, 0, 0, 0)
        content_row.setSpacing(0)

        self._sidebar = Sidebar()
        self._sidebar.page_changed.connect(self._on_page_change)
        content_row.addWidget(self._sidebar)

        self._stack = FadingStack()
        content_row.addWidget(self._stack, 1)

        outer.addLayout(content_row, 1)

        # Custom status bar at the very bottom
        self._status_bar = CyberStatusBar()
        outer.addWidget(self._status_bar)

    def _show_loading(self) -> None:
        self._loading_screen = LoadingScreen(self)
        self._loading_screen.setGeometry(self.rect())
        self._loading_screen.show()
        self._loading_screen.raise_()
        QTimer.singleShot(self._loading_screen.total_ms(), self._finish_loading)

    def _finish_loading(self) -> None:
        if self._loading_screen:
            self._loading_screen.fade_out(self._after_fade)

    def _after_fade(self) -> None:
        if self._loading_screen:
            self._loading_screen.hide()
            self._loading_screen.deleteLater()
            self._loading_screen = None
        self._lazy_load_pages()
        self._sidebar.navigate("dashboard")
        try:
            db.seed_demo_data()
        except Exception:
            pass
        logger.info("CCIT application started successfully", module="MAIN")

    def _lazy_load_pages(self) -> None:
        from ui.phishing_scanner import PhishingScannerPage
        from ui.email_detector import EmailDetectorPage
        from ui.malware_analyzer import MalwareAnalyzerPage
        from ui.network_dashboard import NetworkDashboardPage
        from ui.settings_panel import SettingsPanel
        from ui.reports_view import ReportsViewPage
        from ui.dns_view import DNSAnalyzerPage
        from ui.signatures_view import SignaturesPage

        dashboard = DashboardPage()
        self._pages["dashboard"] = dashboard
        self._stack.addWidget(dashboard)

        constructors = {
            "phishing_url": PhishingScannerPage,
            "email":        EmailDetectorPage,
            "malware":      MalwareAnalyzerPage,
            "network":      NetworkDashboardPage,
            "dns":          DNSAnalyzerPage,
            "signatures":   SignaturesPage,
            "reports":      ReportsViewPage,
            "settings":     SettingsPanel,
        }
        for page_id, cls in constructors.items():
            widget = cls()
            self._pages[page_id] = widget
            self._stack.addWidget(widget)

    def _on_page_change(self, page_id: str) -> None:
        widget = self._pages.get(page_id)
        if widget:
            self._stack.switch_to(widget)
            if hasattr(widget, "refresh"):
                widget.refresh()
            self._sidebar.set_status(
                f"● {page_id.upper().replace('_',' ')}",
                "Module active",
                theme_manager.palette.accent_primary,
            )

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self._loading_screen:
            self._loading_screen.setGeometry(self.rect())

    def closeEvent(self, event) -> None:
        net_page = self._pages.get("network")
        if net_page and hasattr(net_page, "cleanup"):
            net_page.cleanup()
        logger.info("CCIT application closed", module="MAIN")
        event.accept()
