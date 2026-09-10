"""
CCIT — Cyber Crime Investigation Tool
Entry point. Initializes PySide6 application, applies theme, launches main window.
"""

import os
import sys

# ── make sure ccit/ is on the path when launched via `python main.py` ──────
_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_DIR)
for _p in (_DIR, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import json
import traceback
from datetime import datetime

from PySide6.QtCore import Qt, QCoreApplication, QLocale
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QMessageBox


# ── load config ──────────────────────────────────────────────────────────────
_CONFIG_PATH = os.path.join(_DIR, "config", "config.json")
_CONFIG: dict = {}
try:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as _fh:
        _CONFIG = json.load(_fh)
except Exception:
    pass

_THEME   = _CONFIG.get("ui", {}).get("theme", "neon_dark")
_FONT_SZ = int(_CONFIG.get("ui", {}).get("font_size", 12))


def _setup_high_dpi() -> None:
    """Enable HiDPI support before QApplication is created."""
    QCoreApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    # Qt 6 has HiDPI scaling enabled by default; no further config needed.


def _apply_global_font(app: QApplication) -> None:
    font = QFont("Courier New", _FONT_SZ)
    font.setStyleHint(QFont.Monospace)
    app.setFont(font)


def _crash_handler(exc_type, exc_value, exc_tb) -> None:
    """Show a dialog on unhandled exception and log to file."""
    msg = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    crash_log = os.path.join(_DIR, "logs", f"crash_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    os.makedirs(os.path.dirname(crash_log), exist_ok=True)
    try:
        with open(crash_log, "w", encoding="utf-8") as fh:
            fh.write(msg)
    except Exception:
        pass

    try:
        dlg = QMessageBox()
        dlg.setWindowTitle("CCIT — Unhandled Exception")
        dlg.setIcon(QMessageBox.Critical)
        dlg.setText("An unexpected error occurred.")
        dlg.setDetailedText(msg[:2000])
        dlg.exec()
    except Exception:
        print(msg, file=sys.stderr)


def main() -> int:
    _setup_high_dpi()
    app = QApplication(sys.argv)
    app.setApplicationName("CCIT")
    app.setApplicationDisplayName("Cyber Crime Investigation Tool")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("CCIT Security")
    QLocale.setDefault(QLocale(QLocale.English))

    _apply_global_font(app)

    # Install crash handler
    sys.excepthook = _crash_handler

    # Bootstrap theme manager before any UI is created
    from ui.theme import theme_manager
    theme_manager.set_theme(_THEME)
    app.setStyleSheet(theme_manager.stylesheet())

    # Ensure DB is imported and initialized (happens at module level)
    from modules.database import db  # noqa: F401

    # Launch main window
    from ui.main_window import CCITMainWindow
    window = CCITMainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
