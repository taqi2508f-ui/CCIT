"""
CCIT Network Monitor Module
Real-time network connection monitoring, suspicious IP detection, and traffic analysis.
Uses psutil for connection data — no raw socket sniffing (ethical and cross-platform).
All analysis logic is custom-built.
"""

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from modules.logger import logger


SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    135: "MSRPC",
    137: "NetBIOS-NS",
    139: "NetBIOS-SSN",
    143: "IMAP",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit default",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    6667: "IRC (C2 common)",
    8080: "HTTP alt",
    8443: "HTTPS alt",
    8888: "Common C2 port",
    9090: "Common proxy",
    27017: "MongoDB",
}

KNOWN_MALICIOUS_IP_RANGES = [
    ("185.220.101.0", "185.220.101.255"),
    ("185.107.56.0", "185.107.63.255"),
    ("198.96.155.0", "198.96.155.255"),
    ("23.129.64.0", "23.129.64.255"),
]

HIGH_RISK_COUNTRIES_HEURISTIC = {
    "Tor Exit Node IP ranges",
}


@dataclass
class NetworkConnection:
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    status: str = ""
    pid: int = 0
    process_name: str = ""
    protocol: str = "TCP"
    suspicious: bool = False
    risk_reasons: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    bytes_sent: int = 0
    bytes_recv: int = 0


@dataclass
class NetworkSnapshot:
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    total_connections: int = 0
    established: int = 0
    listening: int = 0
    suspicious_count: int = 0
    connections: list[NetworkConnection] = field(default_factory=list)
    bytes_sent_total: int = 0
    bytes_recv_total: int = 0
    active_pids: list[int] = field(default_factory=list)


class NetworkMonitor:
    """
    Polls live network connections and flags suspicious activity.
    Runs in a background thread and notifies registered callbacks.
    """

    def __init__(self, poll_interval: float = 2.0) -> None:
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: list[Callable[[NetworkSnapshot], None]] = []
        self._lock = threading.Lock()
        self._last_snapshot: Optional[NetworkSnapshot] = None
        self._connection_history: list[NetworkConnection] = []
        self._max_history = 500

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="NetMonitor")
        self._thread.start()
        logger.info("Network monitor started", module="NETWORK_MONITOR")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Network monitor stopped", module="NETWORK_MONITOR")

    def register_callback(self, cb: Callable[[NetworkSnapshot], None]) -> None:
        with self._lock:
            self._callbacks.append(cb)

    def unregister_callback(self, cb: Callable[[NetworkSnapshot], None]) -> None:
        with self._lock:
            if cb in self._callbacks:
                self._callbacks.remove(cb)

    def get_last_snapshot(self) -> Optional[NetworkSnapshot]:
        return self._last_snapshot

    def get_connection_history(self, limit: int = 100) -> list[NetworkConnection]:
        return self._connection_history[-limit:]

    def _poll_loop(self) -> None:
        while self._running:
            try:
                snapshot = self._capture_snapshot()
                with self._lock:
                    self._last_snapshot = snapshot
                    for conn in snapshot.connections:
                        if conn.suspicious:
                            self._connection_history.append(conn)
                    if len(self._connection_history) > self._max_history:
                        self._connection_history = self._connection_history[-self._max_history:]
                    callbacks = list(self._callbacks)
                for cb in callbacks:
                    try:
                        cb(snapshot)
                    except Exception as exc:
                        logger.error(f"Network monitor callback error: {exc}", module="NETWORK_MONITOR")
            except Exception as exc:
                logger.error(f"Network monitor poll error: {exc}", module="NETWORK_MONITOR")
            time.sleep(self.poll_interval)

    def _capture_snapshot(self) -> NetworkSnapshot:
        snapshot = NetworkSnapshot()

        if not PSUTIL_AVAILABLE:
            snapshot = self._generate_demo_snapshot()
            return snapshot

        try:
            io = psutil.net_io_counters()
            snapshot.bytes_sent_total = io.bytes_sent
            snapshot.bytes_recv_total = io.bytes_recv
        except Exception:
            pass

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            connections = []

        pids_seen: set[int] = set()
        for conn in connections:
            nc = self._process_connection(conn)
            snapshot.connections.append(nc)
            pids_seen.add(nc.pid)

            snapshot.total_connections += 1
            if conn.status == "ESTABLISHED":
                snapshot.established += 1
            elif conn.status == "LISTEN":
                snapshot.listening += 1
            if nc.suspicious:
                snapshot.suspicious_count += 1

        snapshot.active_pids = list(pids_seen)
        return snapshot

    def _process_connection(self, conn) -> NetworkConnection:
        nc = NetworkConnection()

        try:
            if conn.laddr:
                nc.local_addr = conn.laddr.ip
                nc.local_port = conn.laddr.port
            if conn.raddr:
                nc.remote_addr = conn.raddr.ip
                nc.remote_port = conn.raddr.port
        except Exception:
            pass

        nc.status = conn.status or "UNKNOWN"
        nc.pid = conn.pid or 0
        nc.protocol = "UDP" if conn.type and "DGRAM" in str(conn.type) else "TCP"

        if nc.pid:
            try:
                proc = psutil.Process(nc.pid)
                nc.process_name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                nc.process_name = "unknown"

        self._assess_connection(nc)
        return nc

    def _assess_connection(self, nc: NetworkConnection) -> None:
        reasons: list[str] = []

        if nc.remote_port in SUSPICIOUS_PORTS:
            reasons.append(f"Suspicious remote port {nc.remote_port} ({SUSPICIOUS_PORTS[nc.remote_port]})")

        if nc.remote_addr:
            try:
                addr = ipaddress.ip_address(nc.remote_addr)
                if not addr.is_private and not addr.is_loopback:
                    for start_ip, end_ip in KNOWN_MALICIOUS_IP_RANGES:
                        if (ipaddress.ip_address(start_ip) <= addr <= ipaddress.ip_address(end_ip)):
                            reasons.append(f"IP {nc.remote_addr} in known malicious range")
                            break
            except ValueError:
                pass

        suspicious_processes = {
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
            "bitsadmin.exe", "nc.exe", "netcat", "ncat",
        }
        if nc.process_name.lower() in suspicious_processes and nc.remote_addr:
            reasons.append(f"Suspicious process '{nc.process_name}' has external connection")

        if nc.remote_port in (6667, 6666, 6697):
            reasons.append("IRC port — common C2 channel")

        if reasons:
            nc.suspicious = True
            nc.risk_reasons = reasons

    def _generate_demo_snapshot(self) -> NetworkSnapshot:
        """Demo snapshot when psutil is unavailable."""
        import random
        snap = NetworkSnapshot()
        demo_conns = [
            ("127.0.0.1", 5000, "", 0, "LISTEN", 1234, "python.exe", False),
            ("192.168.1.5", 52341, "8.8.8.8", 443, "ESTABLISHED", 2345, "chrome.exe", False),
            ("192.168.1.5", 52342, "185.220.101.45", 6667, "ESTABLISHED", 3456, "svchost.exe", True),
            ("192.168.1.5", 52343, "93.184.216.34", 80, "ESTABLISHED", 2345, "chrome.exe", False),
            ("192.168.1.5", 52344, "198.96.155.10", 4444, "ESTABLISHED", 4567, "unknown.exe", True),
            ("0.0.0.0", 3389, "", 0, "LISTEN", 888, "svchost.exe", False),
        ]
        for la, lp, ra, rp, status, pid, proc, susp in demo_conns:
            nc = NetworkConnection(
                local_addr=la, local_port=lp, remote_addr=ra, remote_port=rp,
                status=status, pid=pid, process_name=proc, suspicious=susp,
            )
            if susp:
                nc.risk_reasons = [f"Suspicious port {rp}" if rp else "Suspicious activity"]
                snap.suspicious_count += 1
            snap.connections.append(nc)
            snap.total_connections += 1
            if status == "ESTABLISHED":
                snap.established += 1
            elif status == "LISTEN":
                snap.listening += 1
        snap.bytes_sent_total = random.randint(50_000_000, 500_000_000)
        snap.bytes_recv_total = random.randint(100_000_000, 1_000_000_000)
        return snap
