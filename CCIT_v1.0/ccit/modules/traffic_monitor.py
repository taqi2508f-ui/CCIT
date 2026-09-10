"""
CCIT Traffic Monitor Module
Generates real-time traffic statistics, tracks bandwidth, and builds time-series data
for the network dashboard charts. Works with or without psutil (uses demo data if unavailable).
"""

import random
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@dataclass
class TrafficPoint:
    timestamp: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    sent_rate_kbps: float = 0.0
    recv_rate_kbps: float = 0.0
    active_connections: int = 0
    suspicious_connections: int = 0


class TrafficMonitor:
    """
    Samples network I/O counters at a fixed interval and maintains a rolling history.
    Provides callbacks for live chart updates.
    """

    MAX_HISTORY = 120

    def __init__(self, sample_interval: float = 1.0) -> None:
        self.sample_interval = sample_interval
        self._history: deque[TrafficPoint] = deque(maxlen=self.MAX_HISTORY)
        self._callbacks: list[Callable[[TrafficPoint], None]] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._prev_bytes_sent: int = 0
        self._prev_bytes_recv: int = 0
        self._prev_pkts_sent: int = 0
        self._prev_pkts_recv: int = 0
        self._demo_base_sent = random.randint(50_000_000, 200_000_000)
        self._demo_base_recv = random.randint(100_000_000, 500_000_000)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        if PSUTIL_AVAILABLE:
            try:
                io = psutil.net_io_counters()
                self._prev_bytes_sent = io.bytes_sent
                self._prev_bytes_recv = io.bytes_recv
                self._prev_pkts_sent = io.packets_sent
                self._prev_pkts_recv = io.packets_recv
            except Exception:
                pass
        self._thread = threading.Thread(target=self._sample_loop, daemon=True, name="TrafficMon")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def register_callback(self, cb: Callable[[TrafficPoint], None]) -> None:
        with self._lock:
            self._callbacks.append(cb)

    def unregister_callback(self, cb: Callable[[TrafficPoint], None]) -> None:
        with self._lock:
            if cb in self._callbacks:
                self._callbacks.remove(cb)

    def get_history(self, count: int = 60) -> list[TrafficPoint]:
        with self._lock:
            hist = list(self._history)
        return hist[-count:]

    def _sample_loop(self) -> None:
        while self._running:
            try:
                point = self._sample()
                with self._lock:
                    self._history.append(point)
                    callbacks = list(self._callbacks)
                for cb in callbacks:
                    try:
                        cb(point)
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(self.sample_interval)

    def _sample(self) -> TrafficPoint:
        now = datetime.now().strftime("%H:%M:%S")

        if PSUTIL_AVAILABLE:
            try:
                io = psutil.net_io_counters()
                sent = io.bytes_sent
                recv = io.bytes_recv
                pkts_sent = io.packets_sent
                pkts_recv = io.packets_recv

                delta_sent = max(sent - self._prev_bytes_sent, 0)
                delta_recv = max(recv - self._prev_bytes_recv, 0)
                delta_pkts_sent = max(pkts_sent - self._prev_pkts_sent, 0)
                delta_pkts_recv = max(pkts_recv - self._prev_pkts_recv, 0)

                self._prev_bytes_sent = sent
                self._prev_bytes_recv = recv
                self._prev_pkts_sent = pkts_sent
                self._prev_pkts_recv = pkts_recv

                try:
                    connections = psutil.net_connections(kind="inet")
                    active = len(connections)
                except Exception:
                    active = 0

                return TrafficPoint(
                    timestamp=now,
                    bytes_sent=sent,
                    bytes_recv=recv,
                    packets_sent=pkts_sent,
                    packets_recv=pkts_recv,
                    sent_rate_kbps=round(delta_sent / 1024 / self.sample_interval, 2),
                    recv_rate_kbps=round(delta_recv / 1024 / self.sample_interval, 2),
                    active_connections=active,
                    suspicious_connections=0,
                )
            except Exception:
                pass

        return self._demo_sample(now)

    def _demo_sample(self, now: str) -> TrafficPoint:
        sent_rate = random.uniform(5, 150) + (50 if random.random() < 0.1 else 0)
        recv_rate = random.uniform(50, 500) + (200 if random.random() < 0.1 else 0)
        self._demo_base_sent += int(sent_rate * 1024 * self.sample_interval)
        self._demo_base_recv += int(recv_rate * 1024 * self.sample_interval)

        return TrafficPoint(
            timestamp=now,
            bytes_sent=self._demo_base_sent,
            bytes_recv=self._demo_base_recv,
            packets_sent=self._demo_base_sent // 512,
            packets_recv=self._demo_base_recv // 512,
            sent_rate_kbps=round(sent_rate, 2),
            recv_rate_kbps=round(recv_rate, 2),
            active_connections=random.randint(8, 25),
            suspicious_connections=random.randint(0, 3),
        )

    def get_summary(self) -> dict:
        hist = self.get_history(60)
        if not hist:
            return {}
        latest = hist[-1]
        avg_sent = sum(p.sent_rate_kbps for p in hist) / len(hist)
        avg_recv = sum(p.recv_rate_kbps for p in hist) / len(hist)
        peak_sent = max(p.sent_rate_kbps for p in hist)
        peak_recv = max(p.recv_rate_kbps for p in hist)
        return {
            "current_sent_kbps": latest.sent_rate_kbps,
            "current_recv_kbps": latest.recv_rate_kbps,
            "avg_sent_kbps": round(avg_sent, 2),
            "avg_recv_kbps": round(avg_recv, 2),
            "peak_sent_kbps": round(peak_sent, 2),
            "peak_recv_kbps": round(peak_recv, 2),
            "total_bytes_sent": latest.bytes_sent,
            "total_bytes_recv": latest.bytes_recv,
            "active_connections": latest.active_connections,
            "suspicious_connections": latest.suspicious_connections,
        }
