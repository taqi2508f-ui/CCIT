"""
CCIT Sidebar Navigation — v2 Cyberpunk Ultra Edition
Animated neon glow nav buttons, pulsing status indicator, animated bracket logo.
"""

from __future__ import annotations
import math
from typing import Optional

from PySide6.QtCore import Qt, QTimer, Signal, QRectF, QRect, QPoint
from PySide6.QtGui import (QColor, QFont, QLinearGradient, QPainter,
                            QPainterPath, QPen, QBrush)
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton,
                                QSizePolicy, QVBoxLayout, QWidget)

from ui.theme import theme_manager


NAV_ITEMS = [
    ("dashboard",    "⊞", "DASHBOARD",       "System overview and recent alerts"),
    ("phishing_url", "⛓", "PHISHING SCANNER", "Analyze phishing websites"),
    ("email",        "✉", "EMAIL DETECTOR",   "Scan phishing emails"),
    ("malware",      "☣", "MALWARE ANALYZER", "Analyze suspicious files"),
    ("network",      "◉", "NETWORK MONITOR",  "Live traffic and connections"),
    ("dns",          "⊡", "DNS ANALYZER",     "Inspect domain records"),
    ("signatures",   "≡", "SIGNATURES",       "Threat signature database"),
    ("reports",      "▤", "REPORTS",          "Export and view scan reports"),
    ("settings",     "⚙", "SETTINGS",         "Application configuration"),
]


class AnimatedNavButton(QWidget):
    """Custom painted nav button with neon sweep and glow animation."""

    clicked = Signal(str)

    def __init__(self, page_id: str, icon: str, label: str,
                 tooltip: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.page_id = page_id
        self._icon = icon
        self._label = label
        self.setToolTip(tooltip)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(44)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self._active = False
        self._hover = False
        self._sweep = 0.0
        self._glow = 0.0
        self._glow_dir = 1.0

        self._sweep_timer = QTimer(self)
        self._sweep_timer.setInterval(14)
        self._sweep_timer.timeout.connect(self._tick_sweep)

        self._glow_timer = QTimer(self)
        self._glow_timer.setInterval(30)
        self._glow_timer.timeout.connect(self._tick_glow)

    def setActive(self, active: bool) -> None:
        self._active = active
        if active:
            self._glow_timer.start()
        else:
            self._glow_timer.stop()
            self._glow = 0.0
        self.update()

    def enterEvent(self, event) -> None:
        self._hover = True
        self._sweep = 0.0
        self._sweep_timer.start()

    def leaveEvent(self, event) -> None:
        self._hover = False
        self._sweep_timer.stop()
        self._sweep = 0.0
        self.update()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.page_id)

    def _tick_sweep(self) -> None:
        self._sweep = min(1.0, self._sweep + 0.1)
        if self._sweep >= 1.0:
            self._sweep_timer.stop()
        self.update()

    def _tick_glow(self) -> None:
        self._glow += self._glow_dir * 0.06
        self._glow = max(0.0, min(1.0, self._glow))
        if self._glow >= 1.0: self._glow_dir = -1.0
        elif self._glow <= 0.0: self._glow_dir = 1.0
        self.update()

    def paintEvent(self, event) -> None:
        w, h = self.width(), self.height()
        p = theme_manager.palette
        acc = QColor(p.accent_primary)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Background
        if self._active:
            grad = QLinearGradient(0, 0, w, 0)
            a_c = QColor(acc)
            a_c.setAlpha(int(30 + self._glow * 25))
            grad.setColorAt(0.0, a_c)
            grad.setColorAt(1.0, QColor(0, 0, 0, 0))
            painter.fillRect(self.rect(), QBrush(grad))
        elif self._hover:
            grad = QLinearGradient(0, 0, w, 0)
            sweep_x = self._sweep * (w + 80) - 80
            for offset, alpha in [(0.0, 0), (0.3, 12), (0.7, 18), (1.0, 0)]:
                pos = max(0.0, min(1.0, (sweep_x + offset * 80) / w))
                grad.setColorAt(pos, QColor(acc.red(), acc.green(), acc.blue(), alpha))
            painter.fillRect(self.rect(), QBrush(grad))

        # Active left bar
        if self._active:
            bar_alpha = int(200 + self._glow * 55)
            bar_c = QColor(acc)
            bar_c.setAlpha(bar_alpha)
            painter.fillRect(0, 0, 3, h, bar_c)
            # Glow bloom
            bloom_c = QColor(acc)
            bloom_c.setAlpha(int(60 + self._glow * 40))
            painter.fillRect(3, 0, 6, h, bloom_c)
        elif self._hover:
            hover_c = QColor(p.text_secondary)
            hover_c.setAlpha(80)
            painter.fillRect(0, 0, 2, h, hover_c)

        # Bottom separator
        sep_c = QColor(p.border)
        sep_c.setAlpha(120)
        painter.setPen(QPen(sep_c, 1))
        painter.drawLine(8, h - 1, w - 8, h - 1)

        # Icon
        icon_color = QColor(acc) if self._active else QColor(
            p.text_primary if self._hover else p.text_secondary)
        icon_font = QFont("Courier New", 14 if self._active else 12)
        if self._active:
            icon_font.setBold(True)
        painter.setFont(icon_font)
        painter.setPen(QPen(icon_color))
        painter.drawText(QRectF(12, 0, 28, h), Qt.AlignVCenter | Qt.AlignLeft, self._icon)

        # Label
        lbl_color = QColor(acc) if self._active else QColor(
            p.text_primary if self._hover else p.text_secondary)
        lbl_font = QFont("Courier New", 9 if self._active else 9)
        lbl_font.setLetterSpacing(QFont.AbsoluteSpacing, 1.5)
        if self._active:
            lbl_font.setBold(True)
        painter.setFont(lbl_font)
        painter.setPen(QPen(lbl_color))
        painter.drawText(QRectF(44, 0, w - 50, h), Qt.AlignVCenter | Qt.AlignLeft, self._label)

        painter.end()


class LogoWidget(QWidget):
    """Animated CCIT logo with pulsing brackets and glitch effects."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(90)
        self._pulse = 0.0
        self._pulse_dir = 1.0
        self._bracket_offset = 0.0

        self._timer = QTimer(self)
        self._timer.setInterval(30)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _tick(self) -> None:
        self._pulse += self._pulse_dir * 0.03
        self._pulse = max(0.0, min(1.0, self._pulse))
        if self._pulse >= 1.0: self._pulse_dir = -1.0
        elif self._pulse <= 0.0: self._pulse_dir = 1.0
        self._bracket_offset = math.sin(self._pulse * math.pi) * 2
        self.update()

    def paintEvent(self, event) -> None:
        w, h = self.width(), self.height()
        p = theme_manager.palette
        acc = QColor(p.accent_primary)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Background gradient
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, QColor(p.surface_3))
        grad.setColorAt(1, QColor(p.surface))
        painter.fillRect(self.rect(), QBrush(grad))

        # Glow bloom top
        bloom_c = QColor(acc)
        bloom_c.setAlpha(int(15 + self._pulse * 20))
        painter.fillRect(0, 0, w, h, bloom_c)

        # Main logo text
        logo_font = QFont("Courier New", 20, QFont.Bold)
        logo_font.setLetterSpacing(QFont.AbsoluteSpacing, 6)
        painter.setFont(logo_font)

        glow_c = QColor(acc)
        glow_c.setAlpha(int(60 + self._pulse * 80))
        painter.setPen(QPen(glow_c))
        painter.drawText(QRectF(2, 10, w - 4, 36), Qt.AlignCenter, "◈ CCIT")

        # Solid text on top
        painter.setPen(QPen(acc))
        painter.drawText(QRectF(0, 10, w, 36), Qt.AlignCenter, "◈ CCIT")

        # Subtitle
        sub_font = QFont("Courier New", 7)
        sub_font.setLetterSpacing(QFont.AbsoluteSpacing, 1)
        painter.setFont(sub_font)
        painter.setPen(QPen(QColor(p.text_secondary)))
        painter.drawText(QRectF(0, 48, w, 16), Qt.AlignCenter, "CYBER CRIME INVESTIGATION")

        painter.setPen(QPen(QColor(p.text_disabled)))
        ver_font = QFont("Courier New", 7)
        painter.setFont(ver_font)
        painter.drawText(QRectF(0, 64, w, 14), Qt.AlignCenter, "v1.0.0  ·  OFFLINE")

        # Moving scan line
        scan_y = int((h - 4) * ((self._pulse + 1) / 2))
        scan_c = QColor(acc)
        scan_c.setAlpha(40)
        painter.fillRect(0, scan_y, w, 1, scan_c)

        painter.end()


class StatusWidget(QWidget):
    """Animated pulsing status indicator at the bottom of the sidebar."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(64)
        self._status = "● SYSTEM READY"
        self._sub = "All modules loaded"
        self._color = "#00FF41"
        self._pulse = 0.0
        self._pulse_dir = 1.0

        self._timer = QTimer(self)
        self._timer.setInterval(40)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _tick(self) -> None:
        self._pulse += self._pulse_dir * 0.05
        self._pulse = max(0.0, min(1.0, self._pulse))
        if self._pulse >= 1.0: self._pulse_dir = -1.0
        elif self._pulse <= 0.0: self._pulse_dir = 1.0
        self.update()

    def set_status(self, text: str, sub: str = "", color: str = "#00FF41") -> None:
        self._status = text
        self._sub = sub
        self._color = color
        self.update()

    def paintEvent(self, event) -> None:
        w, h = self.width(), self.height()
        p = theme_manager.palette
        acc = QColor(self._color)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Background
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, QColor(p.surface))
        grad.setColorAt(1, QColor(p.background))
        painter.fillRect(self.rect(), QBrush(grad))

        # Top separator with glow
        sep_c = QColor(acc)
        sep_c.setAlpha(int(80 + self._pulse * 80))
        painter.fillRect(0, 0, w, 1, sep_c)

        # Pulsing dot
        dot_r = int(4 + self._pulse * 2)
        dot_c = QColor(acc)
        dot_c.setAlpha(int(150 + self._pulse * 100))
        painter.setBrush(QBrush(dot_c))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPoint(14, 20), dot_r, dot_r)

        # Glow around dot
        glow_c = QColor(acc)
        glow_c.setAlpha(int(30 + self._pulse * 40))
        painter.setBrush(QBrush(glow_c))
        painter.drawEllipse(QPoint(14, 20), dot_r + 5, dot_r + 5)

        # Status text
        painter.setPen(QPen(acc))
        font = QFont("Courier New", 9, QFont.Bold)
        font.setLetterSpacing(QFont.AbsoluteSpacing, 1)
        painter.setFont(font)
        painter.drawText(QRectF(26, 10, w - 30, 20), Qt.AlignVCenter | Qt.AlignLeft, self._status)

        # Sub text
        painter.setPen(QPen(QColor(p.text_secondary)))
        sub_font = QFont("Courier New", 8)
        painter.setFont(sub_font)
        painter.drawText(QRectF(14, 32, w - 18, 18), Qt.AlignVCenter | Qt.AlignLeft, self._sub)

        painter.end()


class Sidebar(QWidget):
    """Fixed sidebar providing animated navigation."""

    page_changed = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(224)
        self._buttons: dict[str, AnimatedNavButton] = {}
        self._active_page = ""
        self._setup_ui()

    def _setup_ui(self) -> None:
        p = theme_manager.palette
        self.setStyleSheet(
            f"QWidget#sidebar {{ background: {p.surface}; border-right: 1px solid {p.border}; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._logo = LogoWidget()
        layout.addWidget(self._logo)

        # Nav section label
        nav_lbl = QLabel("  NAVIGATION")
        nav_lbl.setStyleSheet(
            f"color: {p.text_disabled}; font-size: 8px; letter-spacing: 3px;"
            f"padding: 8px 12px 4px; background: {p.surface};"
        )
        layout.addWidget(nav_lbl)

        for page_id, icon, label, tooltip in NAV_ITEMS:
            btn = AnimatedNavButton(page_id, icon, label, tooltip)
            btn.clicked.connect(self.navigate)
            self._buttons[page_id] = btn
            layout.addWidget(btn)

        layout.addStretch(1)

        self._status_widget = StatusWidget()
        layout.addWidget(self._status_widget)

    def navigate(self, page_id: str) -> None:
        if self._active_page == page_id:
            return
        self._active_page = page_id
        for pid, btn in self._buttons.items():
            btn.setActive(pid == page_id)
        self.page_changed.emit(page_id)

    def set_status(self, text: str, sub: str = "", color: Optional[str] = None) -> None:
        self._status_widget.set_status(text, sub, color or theme_manager.palette.accent_primary)

    def get_active_page(self) -> str:
        return self._active_page
