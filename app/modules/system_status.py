"""System status collector: CPU, memory, disk, uptime, load, and the health of
key security services (ufw, fail2ban, ssh)."""
from __future__ import annotations

import time

import psutil

from app.modules.utils import run_command, have_binary


def _service_active(name: str) -> str:
    if not have_binary("systemctl"):
        return "unknown"
    res = run_command(["systemctl", "is-active", name], timeout=8)
    return res["stdout"].strip() or ("active" if res["ok"] else "inactive")


def get_status() -> dict:
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    try:
        load1, load5, load15 = psutil.getloadavg()
    except (OSError, AttributeError):
        load1 = load5 = load15 = 0.0
    boot = psutil.boot_time()
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "cpu_count": psutil.cpu_count(),
        "load_avg": {"1m": round(load1, 2), "5m": round(load5, 2), "15m": round(load15, 2)},
        "memory": {
            "total": vm.total, "used": vm.used, "available": vm.available,
            "percent": vm.percent,
        },
        "disk": {
            "total": disk.total, "used": disk.used, "free": disk.free,
            "percent": disk.percent,
        },
        "uptime_seconds": int(time.time() - boot),
        "services": {
            "ufw": _service_active("ufw"),
            "fail2ban": _service_active("fail2ban"),
            "ssh": _service_active("ssh"),
        },
        "hostname": _hostname(),
    }


def _hostname() -> str:
    res = run_command(["hostname"], timeout=5)
    return res["stdout"].strip() if res["ok"] else "unknown"
