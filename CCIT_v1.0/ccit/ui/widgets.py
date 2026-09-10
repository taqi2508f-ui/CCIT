"""
CCIT Custom Widgets — v2 Cyberpunk Ultra Edition
3D-style animated stat cards, matrix-rain canvas, glowing arc gauges,
scanline overlays, glitch labels, pulsing indicators, cyber buttons.
"""

from __future__ import annotations

import math
import random
import time
from typing import Optional

from PySide6.QtCore import (Property, QEasingCurve, QPoint, QPropertyAnimation,
                             QRect, QRectF, QSize, Qt, QTimer, Signal)
from PySide6.QtGui import (QBrush, QColor, QFont, QFontMetrics, QLinearGradient,
                            QPainter, QPainterPath, QPen, QPixmap,
                            QRadialGradient, QTextCursor)
from PySide6.QtWidgets import (QFrame, QGraphicsDropShadowEffect, QHBoxLayout,
                                QLabel, QPlainTextEdit, QSizePolicy,
                                QVBoxLayout, QWidget)

from ui.theme import ColorPalette, get_score_color, theme_manager


# ══════════════════════════════════════════════════════════════════════════════
#  Matrix Rain Widget
# ══════════════════════════════════════════════════════════════════════════════

MATRIX_CHARS = (
    "ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ012345789Z:・.\"=*+-<>¦｡"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%&!?<>[]{}|\\/"
)


class MatrixRainWidget(QWidget):
    """Fullscreen animated matrix digital rain background."""

    def __init__(self, parent: Optional[QWidget] = None,
                 color: str = "#00FF41", density: float = 1.0) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._color = QColor(color)
        self._density = density
        self._char_size = 14
        self._columns: list[dict] = []
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        self._fade_pixmap: Optional[QPixmap] = None

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._init_columns()

    def _init_columns(self) -> None:
        w, h = self.width(), self.height()
        if w == 0 or h == 0:
            return
        n_cols = max(1, int(w / self._char_size * self._density))
        self._columns = []
        for i in range(n_cols):
            self._columns.append({
                "x": int(i * (w / n_cols)),
                "y": random.randint(-h, 0),
                "speed": random.uniform(0.5, 2.5),
                "length": random.randint(8, 28),
                "chars": [random.choice(MATRIX_CHARS) for _ in range(30)],
                "bright": random.random() > 0.6,
            })

    def _tick(self) -> None:
        h = self.height()
        for col in self._columns:
            col["y"] += col["speed"] * self._char_size * 0.5
            if col["y"] > h + col["length"] * self._char_size:
                col["y"] = random.randint(-200, -self._char_size * 4)
                col["speed"] = random.uniform(0.5, 2.5)
                col["length"] = random.randint(8, 28)
                col["bright"] = random.random() > 0.6
            # occasionally mutate a char
            if random.random() < 0.05:
                idx = random.randint(0, len(col["chars"]) - 1)
                col["chars"][idx] = random.choice(MATRIX_CHARS)
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, False)

        # Fade trail
        painter.fillRect(self.rect(), QColor(0, 0, 0, 30))

        font = QFont("Courier New", self._char_size - 2)
        font.setBold(True)
        painter.setFont(font)

        cs = self._char_size
        for col in self._columns:
            x = col["x"]
            y_top = int(col["y"])
            length = col["length"]
            for i in range(length):
                y = y_top - i * cs
                if y < -cs or y > self.height():
                    continue
                char = col["chars"][i % len(col["chars"])]
                # Head char — bright white/green
                if i == 0:
                    c = QColor(200, 255, 200, 255) if col["bright"] else QColor(
                        self._color.red(), self._color.green(), self._color.blue(), 255)
                else:
                    alpha = max(20, 220 - int(i * 210 / length))
                    fade = 1.0 - i / length
                    c = QColor(
                        int(self._color.red() * fade * 0.4),
                        int(self._color.green() * fade),
                        int(self._color.blue() * fade * 0.4),
                        alpha,
                    )
                painter.setPen(c)
                painter.drawText(x, y, char)

        painter.end()

    def stop(self) -> None:
        self._timer.stop()

    def start(self) -> None:
        if not self._timer.isActive():
            self._timer.start()


# ══════════════════════════════════════════════════════════════════════════════
#  Scanline Overlay
# ══════════════════════════════════════════════════════════════════════════════

class ScanlineOverlay(QWidget):
    """Transparent scanline effect layered over any widget."""

    def __init__(self, parent: Optional[QWidget] = None,
                 alpha: int = 18, spacing: int = 3) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_NoSystemBackground)
        self._alpha = alpha
        self._spacing = spacing

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        pen = QPen(QColor(0, 0, 0, self._alpha))
        pen.setWidth(1)
        painter.setPen(pen)
        y = 0
        while y < self.height():
            painter.drawLine(0, y, self.width(), y)
            y += self._spacing
        painter.end()


# ══════════════════════════════════════════════════════════════════════════════
#  Glitch Label
# ══════════════════════════════════════════════════════════════════════════════

class GlitchLabel(QLabel):
    """Label that periodically renders a digital glitch distortion effect."""

    def __init__(self, text: str = "", glitch_interval: int = 3000,
                 color: str = "#00FF41", parent: Optional[QWidget] = None) -> None:
        super().__init__(text, parent)
        self._base_text = text
        self._color = color
        self._glitching = False
        self._glitch_chars = "!@#$%^&*[]{}|<>?/\\~`"
        self._glitch_text = text

        self._trigger_timer = QTimer(self)
        self._trigger_timer.setInterval(glitch_interval)
        self._trigger_timer.timeout.connect(self._start_glitch)
        self._trigger_timer.start()

        self._glitch_timer = QTimer(self)
        self._glitch_timer.setInterval(60)
        self._glitch_timer.timeout.connect(self._glitch_tick)
        self._glitch_count = 0
        self._update_style(False)

    def setText(self, text: str) -> None:
        self._base_text = text
        super().setText(text)

    def _update_style(self, glitching: bool) -> None:
        if glitching:
            self.setStyleSheet(
                f"color: #FFFFFF; background: {self._color}; padding: 0 2px; font-weight: bold;"
            )
        else:
            self.setStyleSheet(
                f"color: {self._color}; background: transparent; font-weight: bold;"
            )

    def _start_glitch(self) -> None:
        if not self._base_text:
            return
        self._glitching = True
        self._glitch_count = 0
        self._glitch_timer.start()

    def _glitch_tick(self) -> None:
        self._glitch_count += 1
        if self._glitch_count > 8:
            self._glitch_timer.stop()
            self._glitching = False
            super().setText(self._base_text)
            self._update_style(False)
            return
        # Randomly corrupt some characters
        corrupted = ""
        for ch in self._base_text:
            if ch != " " and random.random() < 0.35:
                corrupted += random.choice(self._glitch_chars)
            else:
                corrupted += ch
        super().setText(corrupted)
        self._update_style(self._glitch_count % 2 == 0)


# ══════════════════════════════════════════════════════════════════════════════
#  Threat Score Gauge  (3-ring animated arc with glow)
# ══════════════════════════════════════════════════════════════════════════════

class ThreatScoreGauge(QWidget):
    """Multi-ring animated threat score gauge with neon glow and pulsing."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._score: int = 0
        self._display_score: float = 0.0
        self._target_score: int = 0
        self._pulse: float = 0.0
        self._pulse_dir: float = 1.0

        self._anim_timer = QTimer(self)
        self._anim_timer.setInterval(16)
        self._anim_timer.timeout.connect(self._tick)
        self._anim_timer.start()

        self.setMinimumSize(170, 170)
        self.setMaximumSize(200, 200)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

    def set_score(self, score: int, animate: bool = True) -> None:
        self._target_score = max(0, min(100, score))
        if not animate:
            self._display_score = float(self._target_score)
            self._score = self._target_score

    def _tick(self) -> None:
        diff = self._target_score - self._display_score
        if abs(diff) > 0.3:
            self._display_score += diff * 0.08
        else:
            self._display_score = float(self._target_score)
            self._score = self._target_score

        self._pulse += self._pulse_dir * 0.04
        self._pulse = max(0.0, min(1.0, self._pulse))
        if self._pulse >= 1.0:
            self._pulse_dir = -1.0
        elif self._pulse <= 0.0:
            self._pulse_dir = 1.0

        self.update()

    def paintEvent(self, event) -> None:
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        score = self._display_score
        p = theme_manager.palette

        color_hex = get_score_color(int(score), p)
        color = QColor(color_hex)
        glow = QColor(color)
        glow.setAlpha(int(80 + self._pulse * 60))

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 0))

        angle_start = -225
        span = int(score / 100 * 270)

        # ── outer glow ring (pulse) ──────────────────────────────────────────
        glow_pen = QPen(glow, 6 + int(self._pulse * 4))
        glow_pen.setCapStyle(Qt.RoundCap)
        painter.setPen(glow_pen)
        outer = 12
        painter.drawArc(
            QRectF(outer, outer, w - 2 * outer, h - 2 * outer),
            angle_start * 16, span * 16,
        )

        # ── background ring ──────────────────────────────────────────────────
        bg_pen = QPen(QColor(p.border), 3)
        painter.setPen(bg_pen)
        m = 18
        painter.drawArc(QRectF(m, m, w - 2 * m, h - 2 * m), -225 * 16, 270 * 16)

        # ── main arc ─────────────────────────────────────────────────────────
        main_pen = QPen(color, 10)
        main_pen.setCapStyle(Qt.RoundCap)
        painter.setPen(main_pen)
        painter.drawArc(QRectF(m, m, w - 2 * m, h - 2 * m), angle_start * 16, span * 16)

        # ── inner ring (thin) ────────────────────────────────────────────────
        inner_c = QColor(color)
        inner_c.setAlpha(100)
        inner_pen = QPen(inner_c, 2)
        inner_pen.setCapStyle(Qt.RoundCap)
        painter.setPen(inner_pen)
        m2 = 30
        painter.drawArc(QRectF(m2, m2, w - 2 * m2, h - 2 * m2), angle_start * 16, span * 16)

        # ── center score text ────────────────────────────────────────────────
        painter.setPen(QPen(color))
        f_big = QFont("Courier New", 28, QFont.Bold)
        painter.setFont(f_big)
        painter.drawText(QRectF(0, cy - 30, w, 44), Qt.AlignCenter, f"{int(score)}")

        f_small = QFont("Courier New", 8)
        f_small.setLetterSpacing(QFont.AbsoluteSpacing, 2)
        painter.setFont(f_small)
        painter.setPen(QPen(QColor(p.text_secondary)))
        painter.drawText(QRectF(0, cy + 18, w, 20), Qt.AlignCenter, "THREAT SCORE")

        # ── tick marks ───────────────────────────────────────────────────────
        painter.setPen(QPen(QColor(p.border), 1))
        for i in range(11):
            angle_deg = -225 + i * 27
            angle_rad = math.radians(angle_deg)
            r_outer = (w - 2 * outer) / 2 - 2
            r_inner = r_outer - 5
            x1 = cx + r_outer * math.cos(angle_rad)
            y1 = cy - r_outer * math.sin(angle_rad)
            x2 = cx + r_inner * math.cos(angle_rad)
            y2 = cy - r_inner * math.sin(angle_rad)
            painter.drawLine(QPoint(int(x1), int(y1)), QPoint(int(x2), int(y2)))

        painter.end()


# ══════════════════════════════════════════════════════════════════════════════
#  Verdict Badge
# ══════════════════════════════════════════════════════════════════════════════

VERDICT_STYLES = {
    "MALICIOUS":  ("#FF0055", "#000000"),
    "PHISHING":   ("#FF0055", "#000000"),
    "HIGH_RISK":  ("#FF6600", "#000000"),
    "SUSPICIOUS": ("#FFAA00", "#000000"),
    "LOW_RISK":   ("#AAFF00", "#000000"),
    "CLEAN":      ("#00FF41", "#000000"),
    "UNKNOWN":    ("#333333", "#888888"),
}


class VerdictBadge(QWidget):
    """Animated verdict badge with glow and pulsing background."""

    def __init__(self, verdict: str = "UNKNOWN", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._verdict = verdict
        self._pulse = 0.0
        self._pulse_dir = 1.0
        self.setMinimumSize(160, 48)
        self.setMaximumHeight(56)
        self._timer = QTimer(self)
        self._timer.setInterval(30)
        self._timer.timeout.connect(self._tick)

    def set_verdict(self, verdict: str) -> None:
        self._verdict = verdict.upper()
        if self._verdict in ("MALICIOUS", "PHISHING", "HIGH_RISK", "SUSPICIOUS"):
            self._timer.start()
        else:
            self._timer.stop()
            self._pulse = 0.0
        self.update()

    def _tick(self) -> None:
        self._pulse += self._pulse_dir * 0.05
        self._pulse = max(0.0, min(1.0, self._pulse))
        if self._pulse >= 1.0: self._pulse_dir = -1.0
        elif self._pulse <= 0.0: self._pulse_dir = 1.0
        self.update()

    def paintEvent(self, event) -> None:
        fg, text = VERDICT_STYLES.get(self._verdict, ("#333333", "#888888"))
        w, h = self.width(), self.height()

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Pulsing glow background
        glow_c = QColor(fg)
        glow_c.setAlpha(int(30 + self._pulse * 50))
        painter.fillRect(self.rect(), glow_c)

        # Border
        border_c = QColor(fg)
        border_c.setAlpha(int(180 + self._pulse * 75))
        pen = QPen(border_c, 2)
        painter.setPen(pen)
        painter.drawRect(1, 1, w - 2, h - 2)

        # Corner brackets
        painter.setPen(QPen(QColor(fg), 2))
        bs = 8
        for bx, by, dx, dy in [(0, 0, 1, 1), (w, 0, -1, 1), (0, h, 1, -1), (w, h, -1, -1)]:
            painter.drawLine(bx, by, bx + dx * bs, by)
            painter.drawLine(bx, by, bx, by + dy * bs)

        # Text
        font = QFont("Courier New", 12, QFont.Bold)
        font.setLetterSpacing(QFont.AbsoluteSpacing, 3)
        painter.setFont(font)
        painter.setPen(QPen(QColor(fg)))
        painter.drawText(QRectF(0, 0, w, h), Qt.AlignCenter, self._verdict)

        painter.end()


# ══════════════════════════════════════════════════════════════════════════════
#  Animated 3D Stat Card
# ══════════════════════════════════════════════════════════════════════════════

class StatCard(QWidget):
    """3D-style stat card with hover sweep animation and neon border glow."""

    def __init__(self, label: str, value: str = "0",
                 accent_color: str = "#00FF41",
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._label = label.upper()
        self._value = value
        self._accent = QColor(accent_color)
        self._hover = False
        self._sweep = 0.0          # 0..1 sweep animation
        self._sweep_timer = QTimer(self)
        self._sweep_timer.setInterval(16)
        self._sweep_timer.timeout.connect(self._tick_sweep)
        self._pulse = 0.0
        self._pulse_dir = 1.0
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(40)
        self._pulse_timer.timeout.connect(self._tick_pulse)
        self._pulse_timer.start()

        self.setMinimumSize(110, 80)
        self.setCursor(Qt.ArrowCursor)

    def set_value(self, value: str) -> None:
        self._value = value
        self.update()

    def set_sub(self, sub: str) -> None:
        self._label = sub.upper()
        self.update()

    def set_accent(self, color: str) -> None:
        self._accent = QColor(color)
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

    def _tick_sweep(self) -> None:
        self._sweep = min(1.0, self._sweep + 0.08)
        if self._sweep >= 1.0:
            self._sweep_timer.stop()
        self.update()

    def _tick_pulse(self) -> None:
        self._pulse += self._pulse_dir * 0.04
        self._pulse = max(0.0, min(1.0, self._pulse))
        if self._pulse >= 1.0: self._pulse_dir = -1.0
        elif self._pulse <= 0.0: self._pulse_dir = 1.0
        self.update()

    def paintEvent(self, event) -> None:
        w, h = self.width(), self.height()
        p = theme_manager.palette
        acc = self._accent

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # ── 3D gradient background ────────────────────────────────────────────
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0.0, QColor(p.surface_3))
        grad.setColorAt(0.4, QColor(p.surface_2))
        grad.setColorAt(1.0, QColor(p.background))
        painter.fillRect(self.rect(), QBrush(grad))

        # ── sweep highlight on hover ──────────────────────────────────────────
        if self._hover and self._sweep < 1.0:
            sweep_grad = QLinearGradient(0, 0, w, 0)
            sweep_x = self._sweep * (w + 60) - 60
            sweep_grad.setColorAt(max(0.0, (sweep_x - 40) / w), QColor(acc.red(), acc.green(), acc.blue(), 0))
            mid = max(0.0, min(1.0, sweep_x / w))
            sweep_grad.setColorAt(mid, QColor(acc.red(), acc.green(), acc.blue(), 45))
            sweep_grad.setColorAt(min(1.0, (sweep_x + 40) / w), QColor(acc.red(), acc.green(), acc.blue(), 0))
            painter.fillRect(self.rect(), QBrush(sweep_grad))

        # ── top accent bar ────────────────────────────────────────────────────
        bar_alpha = int(180 + self._pulse * 75)
        bar_c = QColor(acc)
        bar_c.setAlpha(bar_alpha)
        painter.fillRect(0, 0, w, 2, bar_c)

        # ── border ────────────────────────────────────────────────────────────
        if self._hover:
            border_c = QColor(acc)
            border_c.setAlpha(200)
        else:
            border_c = QColor(p.border)
        painter.setPen(QPen(border_c, 1))
        painter.drawRect(0, 0, w - 1, h - 1)

        # ── bottom glow line ──────────────────────────────────────────────────
        glow_c = QColor(acc)
        glow_c.setAlpha(int(40 + self._pulse * 40))
        painter.fillRect(0, h - 2, w, 2, glow_c)

        # ── corner brackets ───────────────────────────────────────────────────
        bracket_c = QColor(acc)
        bracket_c.setAlpha(160 if self._hover else 80)
        painter.setPen(QPen(bracket_c, 1))
        bs = 6
        painter.drawLine(0, 0, bs, 0)
        painter.drawLine(0, 0, 0, bs)
        painter.drawLine(w - bs, 0, w - 1, 0)
        painter.drawLine(w - 1, 0, w - 1, bs)
        painter.drawLine(0, h - bs, 0, h - 1)
        painter.drawLine(0, h - 1, bs, h - 1)
        painter.drawLine(w - 1, h - bs, w - 1, h - 1)
        painter.drawLine(w - bs, h - 1, w - 1, h - 1)

        # ── value ─────────────────────────────────────────────────────────────
        font_val = QFont("Courier New", 18, QFont.Bold)
        painter.setFont(font_val)
        painter.setPen(QPen(QColor(acc)))
        painter.drawText(QRectF(6, 10, w - 12, h - 30), Qt.AlignCenter, self._value)

        # ── label ─────────────────────────────────────────────────────────────
        font_lbl = QFont("Courier New", 7)
        font_lbl.setLetterSpacing(QFont.AbsoluteSpacing, 1)
        painter.setFont(font_lbl)
        painter.setPen(QPen(QColor(p.text_secondary)))
        painter.drawText(QRectF(4, h - 22, w - 8, 18), Qt.AlignCenter, self._label)

        painter.end()


# ══════════════════════════════════════════════════════════════════════════════
#  Terminal Log Widget with scanlines
# ══════════════════════════════════════════════════════════════════════════════

LOG_COLORS = {
    "INFO":     "#33CC33",
    "DEBUG":    "#005500",
    "WARNING":  "#FFAA00",
    "WARN":     "#FFAA00",
    "ERROR":    "#FF0055",
    "CRITICAL": "#FF00FF",
    "SCAN":     "#00EAFF",
    "SUCCESS":  "#00FF41",
}


class TerminalLogWidget(QPlainTextEdit):
    """Cyberpunk terminal log with color-coded levels and typewriter append."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        p = theme_manager.palette
        self.setReadOnly(True)
        self.setMaximumBlockCount(800)
        self.setStyleSheet(
            f"QPlainTextEdit {{"
            f"background: {p.terminal_bg}; border: 1px solid {p.border};"
            f"border-left: 3px solid {p.accent_primary};"
            f"color: {p.terminal_text}; font-family: 'Courier New'; font-size: 11px;"
            f"padding: 6px;}}"
        )
        self._scanline = ScanlineOverlay(self, alpha=12, spacing=2)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._scanline.setGeometry(self.rect())

    def append_line(self, text: str, level: str = "INFO") -> None:
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        color = LOG_COLORS.get(level.upper(), "#33CC33")
        prefix_map = {
            "INFO": "►", "DEBUG": "·", "WARNING": "⚠", "WARN": "⚠",
            "ERROR": "✖", "CRITICAL": "☠", "SCAN": "◉", "SUCCESS": "✔",
        }
        prefix = prefix_map.get(level.upper(), "►")
        escaped = self._escape(text)
        html = (
            f'<span style="color:#005500;">[{ts}]</span> '
            f'<span style="color:{color};font-weight:bold;">{prefix} {level.upper()}</span> '
            f'<span style="color:{color};">{escaped}</span>'
        )
        self.appendHtml(html)
        self.moveCursor(QTextCursor.End)

    def clear_log(self) -> None:
        self.clear()

    @staticmethod
    def _escape(text: str) -> str:
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ══════════════════════════════════════════════════════════════════════════════
#  Traffic / Network Chart  (dual-line with grid and glow fill)
# ══════════════════════════════════════════════════════════════════════════════

class TrafficChart(QWidget):
    """Animated dual-line chart with neon glow fill and grid overlay."""

    def __init__(self, title: str = "TRAFFIC",
                 color1: str = "#00FF41", color2: str = "#00EAFF",
                 max_points: int = 60, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._title = title
        self._c1 = QColor(color1)
        self._c2 = QColor(color2)
        self._series1: list[float] = []
        self._series2: list[float] = []
        self._max_points = max_points
        self._label1 = "A"
        self._label2 = "B"
        self.setMinimumHeight(120)

    def set_labels(self, l1: str, l2: str) -> None:
        self._label1 = l1
        self._label2 = l2
        self.update()

    def push(self, v1: float, v2: float = 0.0) -> None:
        self._series1.append(max(0.0, v1))
        self._series2.append(max(0.0, v2))
        if len(self._series1) > self._max_points:
            self._series1.pop(0)
            self._series2.pop(0)
        self.update()

    def paintEvent(self, event) -> None:
        w, h = self.width(), self.height()
        p = theme_manager.palette

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Background
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, QColor(p.surface_2))
        grad.setColorAt(1, QColor(p.background))
        painter.fillRect(self.rect(), QBrush(grad))

        pad_l, pad_r, pad_t, pad_b = 46, 10, 26, 30
        chart_w = w - pad_l - pad_r
        chart_h = h - pad_t - pad_b

        # Grid lines
        grid_c = QColor(p.border)
        grid_c.setAlpha(80)
        painter.setPen(QPen(grid_c, 1, Qt.DotLine))
        for i in range(5):
            y = pad_t + int(chart_h * i / 4)
            painter.drawLine(pad_l, y, w - pad_r, y)
        for i in range(7):
            x = pad_l + int(chart_w * i / 6)
            painter.drawLine(x, pad_t, x, h - pad_b)

        # Border
        painter.setPen(QPen(QColor(p.border), 1))
        painter.drawRect(pad_l, pad_t, chart_w, chart_h)

        if not self._series1:
            # Empty placeholder text
            painter.setPen(QPen(QColor(p.text_disabled)))
            painter.setFont(QFont("Courier New", 9))
            painter.drawText(QRectF(pad_l, pad_t, chart_w, chart_h),
                             Qt.AlignCenter, "Waiting for data…")
        else:
            all_vals = self._series1 + self._series2
            max_val = max(all_vals) if max(all_vals) > 0 else 1.0

            def draw_series(series: list[float], color: QColor, filled: bool = True) -> None:
                n = len(series)
                if n < 2:
                    return
                pts = []
                for i, v in enumerate(series):
                    x = pad_l + int(chart_w * i / (self._max_points - 1))
                    y = h - pad_b - int(chart_h * v / max_val)
                    pts.append(QPoint(x, y))

                if filled:
                    path = QPainterPath()
                    path.moveTo(pts[0].x(), h - pad_b)
                    for pt in pts:
                        path.lineTo(pt)
                    path.lineTo(pts[-1].x(), h - pad_b)
                    path.closeSubpath()
                    fill_grad = QLinearGradient(0, pad_t, 0, h - pad_b)
                    fill_c_top = QColor(color)
                    fill_c_top.setAlpha(70)
                    fill_c_bot = QColor(color)
                    fill_c_bot.setAlpha(5)
                    fill_grad.setColorAt(0, fill_c_top)
                    fill_grad.setColorAt(1, fill_c_bot)
                    painter.fillPath(path, QBrush(fill_grad))

                # Glow line (wide, low alpha)
                glow_pen = QPen(QColor(color.red(), color.green(), color.blue(), 50), 6)
                painter.setPen(glow_pen)
                for i in range(len(pts) - 1):
                    painter.drawLine(pts[i], pts[i + 1])

                # Main line
                painter.setPen(QPen(color, 2))
                for i in range(len(pts) - 1):
                    painter.drawLine(pts[i], pts[i + 1])

                # Head dot
                head = pts[-1]
                glow_dot = QColor(color)
                glow_dot.setAlpha(100)
                painter.setBrush(glow_dot)
                painter.setPen(Qt.NoPen)
                painter.drawEllipse(head, 6, 6)
                painter.setBrush(color)
                painter.drawEllipse(head, 3, 3)

            draw_series(self._series1, self._c1, filled=True)
            draw_series(self._series2, self._c2, filled=False)

            # Y-axis labels
            painter.setPen(QPen(QColor(p.text_disabled)))
            painter.setFont(QFont("Courier New", 8))
            for i in range(5):
                v = max_val * (4 - i) / 4
                y = pad_t + int(chart_h * i / 4)
                label = f"{v:.0f}" if v < 1000 else f"{v/1000:.1f}k"
                painter.drawText(QRectF(2, y - 8, pad_l - 4, 16), Qt.AlignRight | Qt.AlignVCenter, label)

        # Title
        painter.setPen(QPen(QColor(p.text_secondary)))
        title_font = QFont("Courier New", 8, QFont.Bold)
        title_font.setLetterSpacing(QFont.AbsoluteSpacing, 2)
        painter.setFont(title_font)
        painter.drawText(QRectF(pad_l, 4, chart_w / 2, 18), Qt.AlignLeft, self._title)

        # Legend
        legend_x = w - pad_r - 120
        for i, (lbl, col) in enumerate([(self._label1, self._c1), (self._label2, self._c2)]):
            lx = legend_x + i * 60
            painter.fillRect(lx, 8, 14, 3, col)
            painter.setPen(QPen(QColor(p.text_secondary)))
            painter.setFont(QFont("Courier New", 7))
            painter.drawText(lx + 16, 12, lbl)

        painter.end()


# ══════════════════════════════════════════════════════════════════════════════
#  Cyber Scan Spinner (triple rotating rings)
# ══════════════════════════════════════════════════════════════════════════════

class ScanSpinner(QWidget):
    """Triple-ring spinning loader with neon glow effect."""

    def __init__(self, size: int = 48, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._size = size
        self._angle1 = 0.0
        self._angle2 = 0.0
        self._angle3 = 0.0
        self._running = False
        self._timer = QTimer(self)
        self._timer.setInterval(20)
        self._timer.timeout.connect(self._rotate)
        self.setFixedSize(size, size)
        self.hide()

    def start(self) -> None:
        self._running = True
        self.show()
        self._timer.start()

    def stop(self) -> None:
        self._running = False
        self._timer.stop()
        self.hide()

    def _rotate(self) -> None:
        self._angle1 = (self._angle1 + 6) % 360
        self._angle2 = (self._angle2 - 4) % 360
        self._angle3 = (self._angle3 + 2) % 360
        self.update()

    def paintEvent(self, event) -> None:
        s = self._size
        p = theme_manager.palette
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 0))

        cx, cy = s / 2, s / 2

        rings = [
            (self._angle1, 4,  s // 2 - 4,  p.accent_primary,   180),
            (self._angle2, 3,  s // 2 - 10, p.accent_tertiary,  120),
            (self._angle3, 2,  s // 2 - 16, p.accent_warn,       90),
        ]
        for angle, width, radius, color_hex, arc_span in rings:
            col = QColor(color_hex)
            # glow
            glow_pen = QPen(QColor(col.red(), col.green(), col.blue(), 40), width + 4)
            glow_pen.setCapStyle(Qt.RoundCap)
            painter.setPen(glow_pen)
            r = radius
            painter.drawArc(QRectF(cx - r, cy - r, r * 2, r * 2),
                            int(angle) * 16, arc_span * 16)
            # main
            pen = QPen(col, width)
            pen.setCapStyle(Qt.RoundCap)
            painter.setPen(pen)
            painter.drawArc(QRectF(cx - r, cy - r, r * 2, r * 2),
                            int(angle) * 16, arc_span * 16)

        painter.end()


# ══════════════════════════════════════════════════════════════════════════════
#  Indicator List Widget
# ══════════════════════════════════════════════════════════════════════════════

class IndicatorListWidget(QWidget):
    """Scrollable list of threat indicator items with severity coloring."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(4, 4, 4, 4)
        self._layout.setSpacing(4)
        self._layout.addStretch()
        self._items: list[QWidget] = []

    def set_indicators(self, indicators: list[str]) -> None:
        self.clear()
        for ind in indicators:
            item = self._make_item(ind)
            self._items.append(item)
            self._layout.insertWidget(self._layout.count() - 1, item)

    def clear(self) -> None:
        for item in self._items:
            item.setParent(None)
            item.deleteLater()
        self._items.clear()

    def _make_item(self, text: str) -> QWidget:
        p = theme_manager.palette
        # Determine severity from keyword
        low_text = text.lower()
        if any(k in low_text for k in ("critical", "ransomware", "keylogger", "malicious", "phishing")):
            color = p.accent_secondary
            prefix = "☠"
        elif any(k in low_text for k in ("suspicious", "warning", "danger", "high")):
            color = p.accent_warn
            prefix = "⚠"
        elif any(k in low_text for k in ("encoding", "redirect", "script")):
            color = p.accent_tertiary
            prefix = "◈"
        else:
            color = p.accent_primary
            prefix = "►"

        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame {{ background: {p.surface}; border: 1px solid {p.border};"
            f"border-left: 3px solid {color}; padding: 0; }}"
        )
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(8, 5, 8, 5)
        layout.setSpacing(8)

        icon = QLabel(prefix)
        icon.setStyleSheet(f"color: {color}; font-size: 12px; min-width: 14px;")
        icon.setFixedWidth(14)

        lbl = QLabel(text[:140])
        lbl.setWordWrap(True)
        lbl.setStyleSheet(f"color: {color}; font-size: 10px; font-family: 'Courier New';")

        layout.addWidget(icon)
        layout.addWidget(lbl, 1)
        return frame
