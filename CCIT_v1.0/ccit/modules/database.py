"""
CCIT Database Module
SQLite-backed persistence for scan history, threat records, settings, and reports.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Generator

from modules.logger import logger


DB_PATH = os.path.join("database", "ccit.db")


class CCITDatabase:
    """Thread-safe SQLite database manager for CCIT."""

    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        except Exception as exc:
            conn.rollback()
            logger.error(f"Database error: {exc}", module="DATABASE")
            raise
        finally:
            conn.close()

    def _initialize(self) -> None:
        """Create all tables if they don't exist."""
        ddl = """
        CREATE TABLE IF NOT EXISTS scan_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type   TEXT NOT NULL,
            target      TEXT NOT NULL,
            result      TEXT,
            threat_score INTEGER DEFAULT 0,
            findings    TEXT,
            status      TEXT DEFAULT 'completed',
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS network_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type  TEXT NOT NULL,
            local_addr  TEXT,
            remote_addr TEXT,
            protocol    TEXT,
            pid         INTEGER,
            process     TEXT,
            suspicious  INTEGER DEFAULT 0,
            details     TEXT,
            recorded_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS threat_records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator   TEXT NOT NULL UNIQUE,
            ioc_type    TEXT NOT NULL,
            threat_level TEXT,
            description TEXT,
            tags        TEXT,
            added_at    TEXT NOT NULL,
            last_seen   TEXT
        );

        CREATE TABLE IF NOT EXISTS reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            report_type TEXT NOT NULL,
            title       TEXT NOT NULL,
            file_path   TEXT,
            format      TEXT DEFAULT 'html',
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS plugin_registry (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            version     TEXT,
            enabled     INTEGER DEFAULT 1,
            file_path   TEXT,
            loaded_at   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_scan_type    ON scan_history(scan_type);
        CREATE INDEX IF NOT EXISTS idx_scan_date    ON scan_history(created_at);
        CREATE INDEX IF NOT EXISTS idx_net_date     ON network_events(recorded_at);
        CREATE INDEX IF NOT EXISTS idx_threat_ioc   ON threat_records(indicator);
        """
        with self._connect() as conn:
            conn.executescript(ddl)
        logger.info("Database initialized", module="DATABASE")

    # ── Scan History ────────────────────────────────────────────────────────

    def save_scan(
        self,
        scan_type: str,
        target: str,
        result: str,
        threat_score: int,
        findings: dict,
        status: str = "completed",
    ) -> int:
        sql = """
            INSERT INTO scan_history
                (scan_type, target, result, threat_score, findings, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        with self._connect() as conn:
            cur = conn.execute(
                sql,
                (
                    scan_type,
                    target,
                    result,
                    threat_score,
                    json.dumps(findings),
                    status,
                    datetime.now().isoformat(),
                ),
            )
            return cur.lastrowid

    def get_scan_history(
        self,
        scan_type: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        if scan_type:
            sql = "SELECT * FROM scan_history WHERE scan_type=? ORDER BY created_at DESC LIMIT ?"
            params: tuple = (scan_type, limit)
        else:
            sql = "SELECT * FROM scan_history ORDER BY created_at DESC LIMIT ?"
            params = (limit,)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def delete_scan(self, scan_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM scan_history WHERE id=?", (scan_id,))

    def clear_scan_history(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM scan_history")

    # ── Network Events ───────────────────────────────────────────────────────

    def save_network_event(
        self,
        event_type: str,
        local_addr: str,
        remote_addr: str,
        protocol: str,
        pid: int,
        process: str,
        suspicious: bool,
        details: dict,
    ) -> None:
        sql = """
            INSERT INTO network_events
                (event_type, local_addr, remote_addr, protocol, pid,
                 process, suspicious, details, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self._connect() as conn:
            conn.execute(
                sql,
                (
                    event_type,
                    local_addr,
                    remote_addr,
                    protocol,
                    pid,
                    process,
                    int(suspicious),
                    json.dumps(details),
                    datetime.now().isoformat(),
                ),
            )

    def get_network_events(
        self,
        suspicious_only: bool = False,
        limit: int = 200,
    ) -> list[dict]:
        if suspicious_only:
            sql = "SELECT * FROM network_events WHERE suspicious=1 ORDER BY recorded_at DESC LIMIT ?"
        else:
            sql = "SELECT * FROM network_events ORDER BY recorded_at DESC LIMIT ?"
        with self._connect() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ── Threat Records ───────────────────────────────────────────────────────

    def add_threat_indicator(
        self,
        indicator: str,
        ioc_type: str,
        threat_level: str,
        description: str,
        tags: list[str],
    ) -> None:
        sql = """
            INSERT OR REPLACE INTO threat_records
                (indicator, ioc_type, threat_level, description, tags, added_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        with self._connect() as conn:
            conn.execute(
                sql,
                (
                    indicator,
                    ioc_type,
                    threat_level,
                    description,
                    json.dumps(tags),
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                ),
            )

    def lookup_indicator(self, indicator: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM threat_records WHERE indicator=?", (indicator,)
            ).fetchone()
        return dict(row) if row else None

    def get_all_indicators(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM threat_records ORDER BY added_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Reports ──────────────────────────────────────────────────────────────

    def save_report_record(
        self,
        report_type: str,
        title: str,
        file_path: str,
        fmt: str = "html",
    ) -> int:
        sql = """
            INSERT INTO reports (report_type, title, file_path, format, created_at)
            VALUES (?, ?, ?, ?, ?)
        """
        with self._connect() as conn:
            cur = conn.execute(
                sql,
                (report_type, title, file_path, fmt, datetime.now().isoformat()),
            )
            return cur.lastrowid

    def get_reports(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM reports ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Settings ─────────────────────────────────────────────────────────────

    def set_setting(self, key: str, value: Any) -> None:
        sql = """
            INSERT OR REPLACE INTO app_settings (key, value, updated_at)
            VALUES (?, ?, ?)
        """
        with self._connect() as conn:
            conn.execute(sql, (key, json.dumps(value), datetime.now().isoformat()))

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM app_settings WHERE key=?", (key,)
            ).fetchone()
        if row:
            return json.loads(row["value"])
        return default

    # ── Stats ────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        with self._connect() as conn:
            total_scans = conn.execute(
                "SELECT COUNT(*) FROM scan_history"
            ).fetchone()[0]
            threats_found = conn.execute(
                "SELECT COUNT(*) FROM scan_history WHERE threat_score > 60"
            ).fetchone()[0]
            network_events = conn.execute(
                "SELECT COUNT(*) FROM network_events"
            ).fetchone()[0]
            suspicious_conn = conn.execute(
                "SELECT COUNT(*) FROM network_events WHERE suspicious=1"
            ).fetchone()[0]
        return {
            "total_scans": total_scans,
            "threats_found": threats_found,
            "network_events": network_events,
            "suspicious_connections": suspicious_conn,
        }

    def seed_demo_data(self) -> None:
        """Populate with realistic demo records for UI demonstration."""
        demo_scans = [
            ("phishing_url", "http://paypa1-secure.com/login", "MALICIOUS", 92,
             {"redirects": 3, "ssl_mismatch": True, "form_action": "http://evil.ru/collect"}),
            ("phishing_url", "https://google.com", "CLEAN", 0, {"redirects": 0}),
            ("phishing_email", "noreply@amaz0n-support.net", "SUSPICIOUS", 78,
             {"spf_fail": True, "malicious_links": 2}),
            ("malware_file", "/tmp/suspicious_update.exe", "HIGH_RISK", 88,
             {"entropy": 7.9, "packer_detected": True}),
            ("malware_file", "/home/user/document.pdf", "CLEAN", 5, {"entropy": 4.1}),
        ]
        for st, tgt, res, score, findings in demo_scans:
            self.save_scan(st, tgt, res, score, findings)

        demo_indicators = [
            ("185.220.101.45", "ip", "HIGH", "Known Tor exit node", ["tor", "proxy"]),
            ("paypa1-secure.com", "domain", "CRITICAL", "Phishing domain impersonating PayPal", ["phishing", "paypal"]),
            ("evil-malware.ru", "domain", "CRITICAL", "C2 server for banking trojan", ["c2", "malware"]),
            ("http://bit.ly/3xEvil", "url", "HIGH", "Shortened URL pointing to exploit kit", ["exploit", "redirect"]),
        ]
        for ind, itype, level, desc, tags in demo_indicators:
            self.add_threat_indicator(ind, itype, level, desc, tags)

        logger.info("Demo data seeded into database", module="DATABASE")


db = CCITDatabase()
