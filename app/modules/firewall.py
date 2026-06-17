"""Firewall / IP-blocking management.

Supports two backends: ``ufw`` and ``iptables``. A persistent JSON store keeps
the list of blocked IPs (with reason + timestamp) so the dashboard survives
restarts and so blocks can be re-applied on boot.

SAFETY: when ``firewall.enforce`` is ``false`` the manager runs in DRY-RUN mode
- it records the block in its store and logs the exact command it *would* run,
but never touches the system firewall. This makes the tool safe to demo/test.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone

from app.config_loader import CONFIG, abspath
from app.modules.logger import get_logger, audit, alert_manager
from app.modules.utils import run_command, is_valid_ip, have_binary

log = get_logger()

_STORE = abspath(CONFIG, "data/blocked_ips.json")


class FirewallManager:
    def __init__(self):
        self._lock = threading.Lock()
        self.backend = CONFIG["firewall"]["backend"]
        self.enforce = CONFIG["firewall"]["enforce"]
        self.chain = CONFIG["firewall"]["iptables_chain"]
        self._blocked: dict[str, dict] = {}
        os.makedirs(os.path.dirname(_STORE), exist_ok=True)
        self._load()
        if self.enforce and self.backend == "iptables":
            self._ensure_chain()

    # ------------------------------------------------------------- persistence
    def _load(self) -> None:
        if os.path.exists(_STORE):
            try:
                with open(_STORE, "r", encoding="utf-8") as fh:
                    self._blocked = json.load(fh)
            except (OSError, json.JSONDecodeError):
                self._blocked = {}

    def _save(self) -> None:
        with open(_STORE, "w", encoding="utf-8") as fh:
            json.dump(self._blocked, fh, indent=2)

    # --------------------------------------------------------------- iptables
    def _ensure_chain(self) -> None:
        # Create custom chain and hook into INPUT if not present.
        run_command(["iptables", "-N", self.chain])  # ignore "exists" error
        check = run_command(["iptables", "-C", "INPUT", "-j", self.chain])
        if not check["ok"]:
            run_command(["iptables", "-I", "INPUT", "-j", self.chain])

    # -------------------------------------------------------------- operations
    def _apply_block(self, ip: str) -> dict:
        if not self.enforce:
            cmd = (["ufw", "deny", "from", ip] if self.backend == "ufw"
                   else ["iptables", "-A", self.chain, "-s", ip, "-j", "DROP"])
            log.info("[DRY-RUN] would run: %s", " ".join(cmd))
            return {"ok": True, "stdout": "dry-run", "stderr": "", "rc": 0}
        if self.backend == "ufw":
            return run_command(["ufw", "insert", "1", "deny", "from", ip])
        return run_command(["iptables", "-A", self.chain, "-s", ip, "-j", "DROP"])

    def _apply_unblock(self, ip: str) -> dict:
        if not self.enforce:
            log.info("[DRY-RUN] would unblock %s", ip)
            return {"ok": True, "stdout": "dry-run", "stderr": "", "rc": 0}
        if self.backend == "ufw":
            return run_command(["ufw", "delete", "deny", "from", ip])
        return run_command(["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"])

    def block_ip(self, ip: str, reason: str = "", actor: str = "system") -> dict:
        if not is_valid_ip(ip):
            return {"ok": False, "error": "invalid IP address"}
        with self._lock:
            if ip in self._blocked:
                return {"ok": True, "already": True, "ip": ip}
            res = self._apply_block(ip)
            if not res["ok"]:
                audit(actor, "block_ip", ip, res.get("stderr", ""), "failed")
                return {"ok": False, "error": res.get("stderr", "command failed")}
            self._blocked[ip] = {
                "ip": ip,
                "reason": reason or "manual block",
                "ts": datetime.now(timezone.utc).isoformat(),
                "actor": actor,
                "enforced": self.enforce,
            }
            self._save()
        audit(actor, "block_ip", ip, reason, "ok")
        alert_manager.add(f"IP blocked: {ip} ({reason or 'manual'})",
                          severity="medium", source="firewall", meta={"ip": ip})
        return {"ok": True, "ip": ip, "enforced": self.enforce}

    def unblock_ip(self, ip: str, actor: str = "system") -> dict:
        with self._lock:
            if ip not in self._blocked:
                return {"ok": False, "error": "IP not in block list"}
            res = self._apply_unblock(ip)
            if not res["ok"]:
                audit(actor, "unblock_ip", ip, res.get("stderr", ""), "failed")
                return {"ok": False, "error": res.get("stderr", "command failed")}
            del self._blocked[ip]
            self._save()
        audit(actor, "unblock_ip", ip, "", "ok")
        alert_manager.add(f"IP unblocked: {ip}", severity="info",
                          source="firewall", meta={"ip": ip})
        return {"ok": True, "ip": ip}

    def list_blocked(self) -> list[dict]:
        with self._lock:
            return sorted(self._blocked.values(), key=lambda x: x["ts"], reverse=True)

    def status(self) -> dict:
        backend_active = False
        rules = ""
        if self.backend == "ufw" and have_binary("ufw"):
            res = run_command(["ufw", "status"])
            backend_active = res["ok"] and "active" in res["stdout"].lower()
            rules = res["stdout"]
        elif self.backend == "iptables" and have_binary("iptables"):
            res = run_command(["iptables", "-L", self.chain, "-n"])
            backend_active = res["ok"]
            rules = res["stdout"]
        return {
            "backend": self.backend,
            "enforce": self.enforce,
            "backend_active": backend_active,
            "blocked_count": len(self._blocked),
            "rules_preview": rules[:4000],
        }

    def reapply_all(self) -> int:
        """Re-apply every stored block to the live firewall (e.g. after reboot)."""
        if not self.enforce:
            return 0
        count = 0
        for ip in list(self._blocked.keys()):
            if self._apply_block(ip)["ok"]:
                count += 1
        return count


firewall_manager = FirewallManager()
