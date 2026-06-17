"""Network traffic monitoring.

Collects active network connections and per-interface I/O counters using
``psutil`` (no root required for most data). Detects suspicious patterns such
as a single remote IP opening an unusually high number of connections, and
raises alerts accordingly.
"""
from __future__ import annotations

import threading
import time
from collections import Counter, defaultdict, deque

import psutil

from app.config_loader import CONFIG
from app.modules.logger import get_logger, alert_manager

log = get_logger()


class NetworkMonitor:
    def __init__(self):
        self._lock = threading.Lock()
        self._connections: list[dict] = []
        self._io_history: deque = deque(maxlen=120)  # ~10 min at 5s interval
        self._last_io = None
        self._last_io_ts = None
        self._alerted_ips: dict[str, float] = {}
        self._top_talkers: Counter = Counter()

    # ----------------------------------------------------------------- collect
    def collect(self) -> None:
        self._collect_connections()
        self._collect_io()

    def _collect_connections(self) -> None:
        track = set(CONFIG["monitoring"]["track_states"])
        conns = []
        per_ip = Counter()
        try:
            raw = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            log.warning("Access denied reading connections; run with more privilege "
                        "for full visibility.")
            raw = []
        for c in raw:
            if c.status not in track and c.status != "LISTEN":
                continue
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            proc_name = ""
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "?"
            entry = {
                "fd": c.fd,
                "proto": "tcp" if c.type == 1 else "udp",
                "laddr": laddr,
                "raddr": raddr,
                "status": c.status,
                "pid": c.pid,
                "process": proc_name,
            }
            conns.append(entry)
            if c.raddr and c.status == "ESTABLISHED":
                per_ip[c.raddr.ip] += 1
        with self._lock:
            self._connections = conns
            self._top_talkers = per_ip
        self._detect_suspicious(per_ip)

    def _detect_suspicious(self, per_ip: Counter) -> None:
        threshold = CONFIG["monitoring"]["connection_threshold"]
        now = time.time()
        for ip, count in per_ip.items():
            if count >= threshold:
                # debounce: don't re-alert same IP within 5 minutes
                if now - self._alerted_ips.get(ip, 0) > 300:
                    self._alerted_ips[ip] = now
                    alert_manager.add(
                        f"Suspicious connection volume from {ip}: {count} established "
                        f"connections (threshold {threshold})",
                        severity="high",
                        source="network_monitor",
                        meta={"ip": ip, "count": count},
                    )

    def _collect_io(self) -> None:
        io = psutil.net_io_counters(pernic=False)
        now = time.time()
        sample = {"ts": now, "bytes_sent": io.bytes_sent, "bytes_recv": io.bytes_recv}
        rate = {"sent_bps": 0.0, "recv_bps": 0.0}
        if self._last_io is not None and self._last_io_ts is not None:
            dt = max(now - self._last_io_ts, 1e-6)
            rate["sent_bps"] = (io.bytes_sent - self._last_io.bytes_sent) / dt
            rate["recv_bps"] = (io.bytes_recv - self._last_io.bytes_recv) / dt
        self._last_io = io
        self._last_io_ts = now
        with self._lock:
            self._io_history.append({**sample, **rate})

    # -------------------------------------------------------------------- query
    def snapshot(self) -> dict:
        with self._lock:
            top = self._top_talkers.most_common(10)
            history = list(self._io_history)
            conns = list(self._connections)
        established = [c for c in conns if c["status"] == "ESTABLISHED"]
        listening = [c for c in conns if c["status"] == "LISTEN"]
        latest = history[-1] if history else {"sent_bps": 0, "recv_bps": 0}
        return {
            "connections": conns,
            "established_count": len(established),
            "listening_count": len(listening),
            "total_count": len(conns),
            "top_talkers": [{"ip": ip, "count": n} for ip, n in top],
            "io_history": history,
            "current_rate": {"sent_bps": latest.get("sent_bps", 0),
                             "recv_bps": latest.get("recv_bps", 0)},
        }


network_monitor = NetworkMonitor()
