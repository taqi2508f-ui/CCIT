"""
CCIT Logger Module
Custom logging system with file and console output, rotation, and color-coded levels.
"""

import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Optional


LOG_COLORS = {
    "DEBUG":    "\033[36m",
    "INFO":     "\033[32m",
    "WARNING":  "\033[33m",
    "ERROR":    "\033[31m",
    "CRITICAL": "\033[35m",
}
RESET = "\033[0m"


class ColorFormatter(logging.Formatter):
    """Adds ANSI color codes to terminal log output."""

    def format(self, record: logging.LogRecord) -> str:
        color = LOG_COLORS.get(record.levelname, "")
        record.levelname = f"{color}{record.levelname}{RESET}"
        record.msg = f"{record.msg}"
        return super().format(record)


class CCITLogger:
    """
    Singleton logger for CCIT.
    Provides file rotation and colored console output.
    """

    _instance: Optional["CCITLogger"] = None
    _initialized: bool = False

    def __new__(cls) -> "CCITLogger":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._setup()

    def _setup(self) -> None:
        os.makedirs("logs", exist_ok=True)

        self.logger = logging.getLogger("CCIT")
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        log_path = os.path.join("logs", "ccit.log")
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=50 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ColorFormatter(
            fmt="%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%H:%M:%S",
        ))
        console_handler.setLevel(logging.INFO)
        self.logger.addHandler(console_handler)

        self._scan_log: list[dict] = []

    def debug(self, msg: str, module: str = "CORE") -> None:
        self.logger.debug(f"[{module}] {msg}")

    def info(self, msg: str, module: str = "CORE") -> None:
        self.logger.info(f"[{module}] {msg}")
        self._append_scan_log("INFO", module, msg)

    def warning(self, msg: str, module: str = "CORE") -> None:
        self.logger.warning(f"[{module}] {msg}")
        self._append_scan_log("WARNING", module, msg)

    def error(self, msg: str, module: str = "CORE") -> None:
        self.logger.error(f"[{module}] {msg}")
        self._append_scan_log("ERROR", module, msg)

    def critical(self, msg: str, module: str = "CORE") -> None:
        self.logger.critical(f"[{module}] {msg}")
        self._append_scan_log("CRITICAL", module, msg)

    def _append_scan_log(self, level: str, module: str, msg: str) -> None:
        self._scan_log.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "module": module,
            "message": msg,
        })
        if len(self._scan_log) > 2000:
            self._scan_log = self._scan_log[-2000:]

    def get_recent_logs(self, count: int = 100) -> list[dict]:
        return self._scan_log[-count:]

    def clear_scan_log(self) -> None:
        self._scan_log.clear()


logger = CCITLogger()
