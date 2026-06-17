"""Intrusion Detection System integration via fail2ban.

Reads fail2ban jail status using ``fail2ban-client`` to surface banned IPs and
jail statistics in the dashboard. Also tails the auth log for failed SSH login
bursts as a lightweight built-in detector when fail2ban is unavailable.
"""
from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque

from app.config_loader import CONFIG
from app.modules.logger import get_logger, alert_manager
from app.modules.utils import run_command, have_binary

log = get_logger()

_JAIL_LIST_RE = re.compile(r"Jail list:\s*(.*)")
_BANNED_RE = re.compile(r"Banned IP list:\s*(.*)")
_NUM_RE = re.compile(r"(\d+)")


class IDSManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._cache: dict = {"available": False, "jails": [], "total_banned": 0}
        self._last_poll = 0
        self._fail_counts: dict[str, int] = defaultdict(int)
        self._seen_lines: deque = deque(maxlen=500)

    def available(self) -> bool:
        return have_binary("fail2ban-client")

    def _client(self, *args: str) -> dict:
        return run_command(["fail2ban-client", *args], timeout=15)

    def get_jails(self) -> list[str]:
        configured = CONFIG["ids"].get("jails") or []
        if configured:
            return configured
        res = self._client("status")
        if not res["ok"]:
            return []
        for line in res["stdout"].splitlines():
            m = _JAIL_LIST_RE.search(line)
            if m:
                return [j.strip() for j in m.group(1).split(",") if j.strip()]
        return []

    def jail_status(self, jail: str) -> dict:
        res = self._client("status", jail)
        info = {"jail": jail, "currently_failed": 0, "total_failed": 0,
                "currently_banned": 0, "total_banned": 0, "banned_ips": []}
        if not res["ok"]:
            return info
        for line in res["stdout"].splitlines():
            low = line.lower()
            nums = _NUM_RE.findall(line)
            if "currently failed" in low and nums:
                info["currently_failed"] = int(nums[0])
            elif "total failed" in low and nums:
                info["total_failed"] = int(nums[0])
            elif "currently banned" in low and nums:
                info["currently_banned"] = int(nums[0])
            elif "total banned" in low and nums:
                info["total_banned"] = int(nums[0])
            m = _BANNED_RE.search(line)
            if m:
                info["banned_ips"] = [ip for ip in m.group(1).split() if ip]
        return info

    def collect(self) -> None:
        # Throttle to at most once per 5s regardless of caller cadence.
        if time.time() - self._last_poll < 4:
            return
        self._last_poll = time.time()
        if not self.available():
            with self._lock:
                self._cache = {"available": False, "jails": [], "total_banned": 0}
            self._builtin_ssh_watch()
            return
        jails = []
        total = 0
        for name in self.get_jails():
            st = self.jail_status(name)
            jails.append(st)
            total += st["currently_banned"]
        with self._lock:
            self._cache = {"available": True, "jails": jails, "total_banned": total}

    def _builtin_ssh_watch(self) -> None:
        """Fallback detector: scan the tail of auth.log for failed SSH logins."""
        path = None
        for candidate in ("/var/log/auth.log", "/var/log/secure"):
            try:
                with open(candidate, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()[-200:]
                path = candidate
                break
            except OSError:
                continue
        if not path:
            return
        ip_re = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
        for line in lines:
            if line in self._seen_lines:
                continue
            self._seen_lines.append(line)
            m = ip_re.search(line)
            if m:
                ip = m.group(1)
                self._fail_counts[ip] += 1
                if self._fail_counts[ip] == 5:
                    alert_manager.add(
                        f"Repeated SSH auth failures from {ip} "
                        f"({self._fail_counts[ip]} attempts)",
                        severity="high", source="ids_builtin", meta={"ip": ip},
                    )

    def ban(self, jail: str, ip: str) -> dict:
        res = self._client("set", jail, "banip", ip)
        return {"ok": res["ok"], "output": res["stdout"] or res["stderr"]}

    def unban(self, jail: str, ip: str) -> dict:
        res = self._client("set", jail, "unbanip", ip)
        return {"ok": res["ok"], "output": res["stdout"] or res["stderr"]}

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._cache)


ids_manager = IDSManager()
