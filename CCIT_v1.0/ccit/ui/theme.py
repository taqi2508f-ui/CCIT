"""
CCIT Theme System — v2 Cyberpunk Ultra Edition
Deep-black surfaces, vivid neon accents, 3D-depth gradients, glow metadata.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ColorPalette:
    # ── Core surfaces (true black base) ─────────────────────────────────────
    background:       str = "#000000"
    surface:          str = "#030d03"
    surface_2:        str = "#061306"
    surface_3:        str = "#091909"

    # ── Borders ──────────────────────────────────────────────────────────────
    border:           str = "#0a200a"
    border_highlight: str = "#00FF41"
    border_active:    str = "#00FF41"

    # ── Neon accents ─────────────────────────────────────────────────────────
    accent_primary:   str = "#00FF41"   # matrix green
    accent_secondary: str = "#FF0055"   # hot red
    accent_tertiary:  str = "#00EAFF"   # electric cyan
    accent_warn:      str = "#FFAA00"   # amber
    accent_purple:    str = "#BF00FF"   # violet
    accent_lime:      str = "#AAFF00"   # lime

    # ── Text ─────────────────────────────────────────────────────────────────
    text_primary:     str = "#D0FFD0"
    text_secondary:   str = "#33CC33"
    text_disabled:    str = "#0D330D"
    text_accent:      str = "#00FF41"
    text_danger:      str = "#FF0055"
    text_warn:        str = "#FFAA00"
    text_info:        str = "#00EAFF"
    text_inverse:     str = "#000000"

    # ── Terminal ─────────────────────────────────────────────────────────────
    terminal_bg:      str = "#000000"
    terminal_text:    str = "#00FF41"

    # ── Buttons ──────────────────────────────────────────────────────────────
    button_primary:   str = "#030d03"
    button_hover:     str = "#0a220a"
    button_active:    str = "#0f330f"
    button_danger:    str = "#150000"
    button_danger_hover: str = "#300000"

    # ── Scrollbar ────────────────────────────────────────────────────────────
    scrollbar_bg:     str = "#000000"
    scrollbar_handle: str = "#003300"

    # ── Charts ───────────────────────────────────────────────────────────────
    chart_line_1:     str = "#00FF41"
    chart_line_2:     str = "#00EAFF"
    chart_line_3:     str = "#FF0055"
    chart_line_4:     str = "#FFAA00"

    # ── Score palette ────────────────────────────────────────────────────────
    score_clean:      str = "#00FF41"
    score_low:        str = "#AAFF00"
    score_medium:     str = "#FFAA00"
    score_high:       str = "#FF6600"
    score_critical:   str = "#FF0055"
    score_extreme:    str = "#FF00FF"


PALETTES: dict[str, ColorPalette] = {
    "neon_dark": ColorPalette(),

    "cyber_blue": ColorPalette(
        background="#000508",
        surface="#000d1a",
        surface_2="#001533",
        surface_3="#001f40",
        border="#002244",
        border_highlight="#00AAFF",
        border_active="#00AAFF",
        accent_primary="#00AAFF",
        accent_secondary="#FF6600",
        accent_tertiary="#00FFCC",
        accent_warn="#FFAA00",
        accent_purple="#FF00AA",
        accent_lime="#00FFCC",
        text_primary="#D0EEFF",
        text_secondary="#3399FF",
        text_disabled="#0D2244",
        text_accent="#00AAFF",
        text_danger="#FF6600",
        text_warn="#FFAA00",
        text_info="#00FFCC",
        text_inverse="#000000",
        terminal_bg="#000000",
        terminal_text="#00AAFF",
        button_primary="#000d1a",
        button_hover="#001833",
        button_active="#002244",
        button_danger="#150A00",
        button_danger_hover="#301500",
        scrollbar_bg="#000508",
        scrollbar_handle="#002244",
        chart_line_1="#00AAFF",
        chart_line_2="#00FFCC",
        chart_line_3="#FF6600",
        chart_line_4="#FFAA00",
        score_clean="#00AAFF",
        score_low="#00FFCC",
        score_medium="#FFAA00",
        score_high="#FF6600",
        score_critical="#FF0055",
        score_extreme="#FF00FF",
    ),

    "red_alert": ColorPalette(
        background="#050000",
        surface="#120000",
        surface_2="#1f0000",
        surface_3="#2a0000",
        border="#350000",
        border_highlight="#FF0055",
        border_active="#FF0055",
        accent_primary="#FF0055",
        accent_secondary="#FF6600",
        accent_tertiary="#FF00FF",
        accent_warn="#FFAA00",
        accent_purple="#AA00FF",
        accent_lime="#FFFF00",
        text_primary="#FFD0D0",
        text_secondary="#FF4444",
        text_disabled="#330000",
        text_accent="#FF0055",
        text_danger="#FF6600",
        text_warn="#FFAA00",
        text_info="#FF00FF",
        text_inverse="#000000",
        terminal_bg="#000000",
        terminal_text="#FF0055",
        button_primary="#120000",
        button_hover="#200000",
        button_active="#2a0000",
        button_danger="#1a0008",
        button_danger_hover="#330010",
        scrollbar_bg="#050000",
        scrollbar_handle="#350000",
        chart_line_1="#FF0055",
        chart_line_2="#FF6600",
        chart_line_3="#FF00FF",
        chart_line_4="#FFAA00",
        score_clean="#00FF41",
        score_low="#AAFF00",
        score_medium="#FFAA00",
        score_high="#FF6600",
        score_critical="#FF0055",
        score_extreme="#FF00FF",
    ),

    "ghost_white": ColorPalette(
        background="#F5F5F5",
        surface="#FFFFFF",
        surface_2="#EAEAEA",
        surface_3="#DDDDDD",
        border="#BBCCBB",
        border_highlight="#007700",
        border_active="#007700",
        accent_primary="#007700",
        accent_secondary="#CC0033",
        accent_tertiary="#0055AA",
        accent_warn="#AA6600",
        accent_purple="#660099",
        accent_lime="#447700",
        text_primary="#002200",
        text_secondary="#224422",
        text_disabled="#AAAAAA",
        text_accent="#007700",
        text_danger="#CC0033",
        text_warn="#AA6600",
        text_info="#0055AA",
        text_inverse="#FFFFFF",
        terminal_bg="#111111",
        terminal_text="#00CC44",
        button_primary="#EAEAEA",
        button_hover="#D5E5D5",
        button_active="#C5D5C5",
        button_danger="#F5E0E0",
        button_danger_hover="#EEC0C0",
        scrollbar_bg="#DDDDDD",
        scrollbar_handle="#AACCAA",
        chart_line_1="#007700",
        chart_line_2="#0055AA",
        chart_line_3="#CC0033",
        chart_line_4="#AA6600",
        score_clean="#007700",
        score_low="#447700",
        score_medium="#AA6600",
        score_high="#CC3300",
        score_critical="#CC0033",
        score_extreme="#660099",
    ),
}


def get_score_color(score: int, palette: Optional[ColorPalette] = None) -> str:
    p = palette or PALETTES["neon_dark"]
    if score >= 90: return p.score_extreme
    if score >= 75: return p.score_critical
    if score >= 55: return p.score_high
    if score >= 35: return p.score_medium
    if score >= 15: return p.score_low
    return p.score_clean


def build_stylesheet(palette: Optional[ColorPalette] = None) -> str:
    p = palette or PALETTES["neon_dark"]
    return f"""
/* ═══════════════════════════════════════════════════════════
   CCIT CYBERPUNK STYLESHEET v2 — ULTRA EDITION
   ═══════════════════════════════════════════════════════════ */

QMainWindow, QDialog {{
    background: {p.background};
    color: {p.text_primary};
    font-family: "Courier New", Courier, monospace;
    font-size: 11px;
}}
QWidget {{
    background: transparent;
    color: {p.text_primary};
    font-family: "Courier New", Courier, monospace;
    font-size: 11px;
    selection-background-color: {p.accent_primary};
    selection-color: {p.text_inverse};
}}
QLabel {{
    background: transparent;
    color: {p.text_primary};
}}

/* ── GROUP BOX ──────────────────────────────────────────── */
QGroupBox {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {p.surface_2},
        stop:1 {p.surface});
    border: 1px solid {p.border};
    border-top: 2px solid {p.accent_primary};
    border-radius: 0px;
    margin-top: 20px;
    padding: 12px 10px 10px 10px;
    color: {p.accent_primary};
    font-size: 9px;
    font-weight: bold;
    letter-spacing: 3px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 14px;
    top: 0px;
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {p.surface_3},
        stop:1 {p.background});
    color: {p.accent_primary};
    border: 1px solid {p.border};
    border-top: 1px solid {p.accent_primary};
    padding: 2px 10px;
    font-size: 9px;
    letter-spacing: 3px;
}}

/* ── PUSH BUTTONS ───────────────────────────────────────── */
QPushButton {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {p.surface_3},
        stop:0.4 {p.surface_2},
        stop:0.6 {p.surface},
        stop:1 {p.background});
    color: {p.accent_primary};
    border: 1px solid {p.accent_primary};
    border-top: 1px solid {p.text_secondary};
    border-radius: 0px;
    padding: 6px 16px;
    font-family: "Courier New";
    font-size: 10px;
    font-weight: bold;
    letter-spacing: 2px;
    min-height: 28px;
}}
QPushButton:hover {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {p.button_hover},
        stop:1 {p.button_primary});
    color: {p.text_primary};
    border: 1px solid {p.accent_primary};
    border-top: 1px solid {p.accent_primary};
}}
QPushButton:pressed {{
    background: {p.accent_primary};
    color: {p.text_inverse};
    border: 1px solid {p.text_secondary};
    padding-top: 8px;
    padding-bottom: 4px;
}}
QPushButton:disabled {{
    background: {p.background};
    color: {p.text_disabled};
    border: 1px solid {p.border};
}}
QPushButton[class="danger"] {{
    border-color: {p.accent_secondary};
    color: {p.accent_secondary};
}}
QPushButton[class="danger"]:hover {{
    background: {p.accent_secondary};
    color: {p.text_inverse};
}}

/* ── LINE EDIT ──────────────────────────────────────────── */
QLineEdit {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-bottom: 2px solid {p.accent_primary};
    color: {p.text_primary};
    padding: 6px 12px;
    font-family: "Courier New";
    font-size: 11px;
    border-radius: 0px;
    selection-background-color: {p.accent_primary};
    selection-color: {p.text_inverse};
}}
QLineEdit:focus {{
    border: 1px solid {p.accent_primary};
    border-bottom: 2px solid {p.accent_primary};
    background: {p.surface_2};
}}

/* ── PLAIN TEXT EDIT ────────────────────────────────────── */
QPlainTextEdit {{
    background: {p.terminal_bg};
    border: 1px solid {p.border};
    border-left: 3px solid {p.accent_primary};
    color: {p.terminal_text};
    padding: 8px;
    font-family: "Courier New";
    font-size: 11px;
    selection-background-color: {p.accent_primary};
    selection-color: {p.text_inverse};
}}
QPlainTextEdit:focus {{
    border: 1px solid {p.accent_primary};
    border-left: 3px solid {p.accent_primary};
}}

/* ── COMBO BOX ──────────────────────────────────────────── */
QComboBox {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-bottom: 2px solid {p.accent_primary};
    color: {p.text_primary};
    padding: 5px 12px;
    font-family: "Courier New";
    font-size: 10px;
    min-height: 26px;
    border-radius: 0px;
}}
QComboBox:hover {{
    border-color: {p.accent_primary};
    background: {p.surface_2};
}}
QComboBox::drop-down {{ border: none; width: 24px; }}
QComboBox::down-arrow {{
    width: 8px;
    height: 8px;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 6px solid {p.accent_primary};
    margin-right: 6px;
}}
QComboBox QAbstractItemView {{
    background: {p.surface_2};
    border: 1px solid {p.accent_primary};
    color: {p.text_primary};
    selection-background-color: {p.accent_primary};
    selection-color: {p.text_inverse};
    outline: none;
    font-size: 10px;
}}

/* ── SPIN BOX ───────────────────────────────────────────── */
QSpinBox, QDoubleSpinBox {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-bottom: 2px solid {p.accent_primary};
    color: {p.text_primary};
    padding: 4px 8px;
    font-family: "Courier New";
    border-radius: 0px;
}}
QSpinBox::up-button, QDoubleSpinBox::up-button,
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    background: {p.surface_2};
    border: 1px solid {p.border};
    width: 18px;
}}

/* ── CHECK BOX ──────────────────────────────────────────── */
QCheckBox {{
    color: {p.text_primary};
    font-family: "Courier New";
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {p.accent_primary};
    background: {p.surface};
}}
QCheckBox::indicator:checked {{
    background: {p.accent_primary};
    border: 1px solid {p.accent_primary};
}}

/* ── TAB WIDGET ─────────────────────────────────────────── */
QTabWidget::pane {{
    border: 1px solid {p.border};
    border-top: 2px solid {p.accent_primary};
    background: {p.surface};
}}
QTabBar::tab {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {p.surface_2},
        stop:1 {p.background});
    color: {p.text_secondary};
    border: 1px solid {p.border};
    border-bottom: none;
    padding: 6px 18px;
    font-family: "Courier New";
    font-size: 9px;
    letter-spacing: 2px;
    margin-right: 1px;
}}
QTabBar::tab:selected {{
    background: {p.surface};
    color: {p.accent_primary};
    border-top: 2px solid {p.accent_primary};
    border-bottom: none;
    font-weight: bold;
    letter-spacing: 2px;
}}
QTabBar::tab:hover:!selected {{
    background: {p.surface_2};
    color: {p.text_primary};
}}

/* ── TABLE WIDGET ───────────────────────────────────────── */
QTableWidget {{
    background: {p.surface};
    alternate-background-color: {p.surface_2};
    border: 1px solid {p.border};
    gridline-color: {p.border};
    color: {p.text_primary};
    font-family: "Courier New";
    font-size: 10px;
    selection-background-color: {p.button_active};
    selection-color: {p.accent_primary};
    outline: none;
}}
QTableWidget::item {{
    padding: 4px 8px;
    border: none;
}}
QTableWidget::item:selected {{
    background: {p.button_active};
    color: {p.accent_primary};
    border-left: 2px solid {p.accent_primary};
}}
QHeaderView::section {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 {p.surface_3},
        stop:1 {p.surface});
    color: {p.accent_primary};
    border: none;
    border-right: 1px solid {p.border};
    border-bottom: 1px solid {p.accent_primary};
    padding: 5px 8px;
    font-family: "Courier New";
    font-size: 9px;
    font-weight: bold;
    letter-spacing: 2px;
}}

/* ── SCROLL BARS ────────────────────────────────────────── */
QScrollBar:vertical {{
    background: {p.scrollbar_bg};
    width: 6px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {p.border_highlight};
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: {p.accent_primary};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {p.scrollbar_bg};
    height: 6px;
    border: none;
}}
QScrollBar::handle:horizontal {{
    background: {p.border_highlight};
    min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {p.accent_primary};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── SPLITTER ───────────────────────────────────────────── */
QSplitter::handle {{ background: {p.border}; }}
QSplitter::handle:vertical {{ height: 2px; }}
QSplitter::handle:horizontal {{ width: 2px; }}
QSplitter::handle:hover {{ background: {p.accent_primary}; }}

/* ── STATUS BAR ─────────────────────────────────────────── */
QStatusBar {{
    background: {p.surface};
    color: {p.text_secondary};
    border-top: 1px solid {p.border};
    font-size: 10px;
    font-family: "Courier New";
    padding: 0 8px;
}}

/* ── SCROLL AREA ────────────────────────────────────────── */
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}

/* ── TOOL TIP ───────────────────────────────────────────── */
QToolTip {{
    background: {p.surface_2};
    color: {p.accent_primary};
    border: 1px solid {p.accent_primary};
    font-family: "Courier New";
    font-size: 10px;
    padding: 4px 8px;
}}

/* ── FORM ───────────────────────────────────────────────── */
QFormLayout QLabel {{
    color: {p.text_secondary};
    font-size: 10px;
    letter-spacing: 1px;
}}
"""


class ThemeManager:
    _instance: Optional["ThemeManager"] = None

    def __new__(cls) -> "ThemeManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._name = "neon_dark"
        self._palette = PALETTES["neon_dark"]
        self._sheet = build_stylesheet(self._palette)

    @property
    def palette(self) -> ColorPalette:
        return self._palette

    @property
    def name(self) -> str:
        return self._name

    def set_theme(self, theme_name: str) -> str:
        if theme_name in PALETTES:
            self._name = theme_name
            self._palette = PALETTES[theme_name]
            self._sheet = build_stylesheet(self._palette)
        return self._sheet

    def stylesheet(self) -> str:
        return self._sheet

    def score_color(self, score: int) -> str:
        return get_score_color(score, self._palette)

    def available_themes(self) -> list[str]:
        return list(PALETTES.keys())


theme_manager = ThemeManager()
