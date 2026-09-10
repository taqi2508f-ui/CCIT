"""
CCIT Update Checker Module
Offline-first version management. Checks for updates against a configurable endpoint.
Runs in background — never blocks the UI.
"""

import json
import threading
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from modules.logger import logger

CURRENT_VERSION = "1.0.0"


@dataclass
class VersionInfo:
    current: str = CURRENT_VERSION
    latest: str = CURRENT_VERSION
    update_available: bool = False
    release_notes: str = ""
    download_url: str = ""
    checked_at: str = field(default_factory=lambda: datetime.now().isoformat())
    error: Optional[str] = None


class UpdateChecker:
    """
    Checks for CCIT updates from a configurable URL.
    Operates fully offline if update_url is empty or unreachable.
    """

    def __init__(self, update_url: str = "", timeout: int = 5) -> None:
        self.update_url = update_url
        self.timeout = timeout
        self._last_check: Optional[VersionInfo] = None
        self._callbacks: list[Callable[[VersionInfo], None]] = []

    def check_async(self) -> None:
        thread = threading.Thread(target=self._check, daemon=True, name="UpdateCheck")
        thread.start()

    def check_sync(self) -> VersionInfo:
        return self._check()

    def register_callback(self, cb: Callable[[VersionInfo], None]) -> None:
        self._callbacks.append(cb)

    def get_last_check(self) -> Optional[VersionInfo]:
        return self._last_check

    def _check(self) -> VersionInfo:
        info = VersionInfo()

        if not self.update_url:
            info.error = "No update URL configured (offline mode)"
            info.release_notes = "CCIT is running in offline mode. All features are available locally."
            self._last_check = info
            logger.info("Update check skipped — offline mode", module="UPDATE_CHECKER")
            return info

        try:
            req = urllib.request.Request(
                self.update_url,
                headers={"User-Agent": f"CCIT/{CURRENT_VERSION}"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())

            latest = data.get("version", CURRENT_VERSION)
            info.latest = latest
            info.release_notes = data.get("release_notes", "")
            info.download_url = data.get("download_url", "")
            info.update_available = self._version_gt(latest, CURRENT_VERSION)

            if info.update_available:
                logger.info(f"Update available: {CURRENT_VERSION} → {latest}", module="UPDATE_CHECKER")
            else:
                logger.info("CCIT is up to date", module="UPDATE_CHECKER")

        except Exception as exc:
            info.error = str(exc)
            logger.warning(f"Update check failed: {exc}", module="UPDATE_CHECKER")

        self._last_check = info
        for cb in self._callbacks:
            try:
                cb(info)
            except Exception:
                pass

        return info

    @staticmethod
    def _version_gt(a: str, b: str) -> bool:
        try:
            a_parts = [int(x) for x in a.split(".")]
            b_parts = [int(x) for x in b.split(".")]
            for ap, bp in zip(a_parts, b_parts):
                if ap > bp:
                    return True
                if ap < bp:
                    return False
            return len(a_parts) > len(b_parts)
        except Exception:
            return False
