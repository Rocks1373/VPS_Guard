"""Offensive / security-testing toolkit (Nmap integration).

Provides asynchronous, authorization-gated scans:
  * port scan (TCP connect / SYN)
  * service & version detection
  * OS detection
  * network reconnaissance (host discovery / ping sweep)
  * basic vulnerability scan (nmap --script vuln)

SAFETY GUARDRAILS
-----------------
Every scan is checked against the configured allow/deny lists and requires an
explicit ``authorized=True`` acknowledgement from the caller (which the UI ties
to a checkbox stating the user has permission to test the target). All scans are
written to the audit log. This keeps the offensive tooling firmly in the
"authorized testing / bug bounty" lane.
"""
from __future__ import annotations

import threading
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from app.config_loader import CONFIG
from app.modules.logger import get_logger, audit, alert_manager
from app.modules.utils import run_command, is_valid_target, target_in_scope, have_binary

log = get_logger()

# Predefined scan profiles -> nmap argument templates. Kept as fixed lists so
# user input is never interpolated into the command string.
SCAN_PROFILES = {
    "ping_sweep": {
        "label": "Host Discovery (ping sweep)",
        "args": ["-sn", "-T4"],
        "desc": "Discover live hosts in a network range without port scanning.",
    },
    "quick_port": {
        "label": "Quick Port Scan (top 100)",
        "args": ["-T4", "-F"],
        "desc": "Fast scan of the 100 most common ports.",
    },
    "full_port": {
        "label": "Full TCP Port Scan (1-65535)",
        "args": ["-T4", "-p-"],
        "desc": "Scan every TCP port. Slower but thorough.",
    },
    "service_detect": {
        "label": "Service & Version Detection",
        "args": ["-T4", "-sV", "--version-intensity", "5"],
        "desc": "Identify services and their versions on open ports.",
    },
    "os_detect": {
        "label": "OS & Service Detection",
        "args": ["-T4", "-sV", "-O"],
        "desc": "Attempt OS fingerprinting plus service detection (needs root).",
    },
    "vuln_scan": {
        "label": "Vulnerability Scan (NSE vuln scripts)",
        "args": ["-T4", "-sV", "--script", "vuln"],
        "desc": "Run Nmap's vulnerability NSE scripts. Noisy & intrusive - "
                "authorized targets only.",
    },
}


class ScanManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._scans: dict[str, dict] = {}
        self._active = 0

    # --------------------------------------------------------------- launching
    def launch(self, target: str, profile: str, ports: str = "",
               authorized: bool = False, actor: str = "user") -> dict:
        if not CONFIG["offensive"]["enabled"]:
            return {"ok": False, "error": "Offensive toolkit is disabled in config."}
        if profile not in SCAN_PROFILES:
            return {"ok": False, "error": f"unknown profile '{profile}'"}
        if not have_binary(CONFIG["offensive"]["nmap_path"]):
            return {"ok": False, "error": "nmap is not installed on this host."}
        if not is_valid_target(target):
            return {"ok": False, "error": "invalid target (expect IP, CIDR or hostname)"}

        if CONFIG["offensive"]["require_authorization"] and not authorized:
            return {"ok": False, "error": "authorization acknowledgement required "
                                          "before scanning a target"}

        allowed, reason = target_in_scope(
            target,
            CONFIG["offensive"]["target_allowlist"],
            CONFIG["offensive"]["target_denylist"],
        )
        if not allowed:
            audit(actor, "scan_blocked", target, reason, "denied")
            alert_manager.add(f"Blocked unauthorized scan attempt on {target}: {reason}",
                              severity="medium", source="scanner",
                              meta={"target": target})
            return {"ok": False, "error": f"target out of scope: {reason}"}

        with self._lock:
            if self._active >= CONFIG["offensive"]["max_concurrent_scans"]:
                return {"ok": False, "error": "max concurrent scans reached; "
                                              "wait for a scan to finish"}
            scan_id = uuid.uuid4().hex[:12]
            record = {
                "id": scan_id,
                "target": target,
                "profile": profile,
                "profile_label": SCAN_PROFILES[profile]["label"],
                "ports": ports,
                "status": "running",
                "started": datetime.now(timezone.utc).isoformat(),
                "finished": None,
                "actor": actor,
                "summary": {},
                "hosts": [],
                "raw": "",
                "error": "",
            }
            self._scans[scan_id] = record
            self._active += 1

        audit(actor, "scan_start", target, f"profile={profile} ports={ports}", "ok")
        thread = threading.Thread(target=self._run, args=(scan_id, target, profile, ports),
                                  daemon=True)
        thread.start()
        return {"ok": True, "scan_id": scan_id}

    # ----------------------------------------------------------------- running
    def _run(self, scan_id: str, target: str, profile: str, ports: str) -> None:
        nmap = CONFIG["offensive"]["nmap_path"]
        args = [nmap] + SCAN_PROFILES[profile]["args"]
        # Only allow a simple, validated port spec (digits, commas, dashes).
        if ports and profile not in ("ping_sweep",):
            clean = ports.replace(" ", "")
            if all(ch.isdigit() or ch in ",-" for ch in clean) and clean:
                args += ["-p", clean]
        # XML output to stdout for reliable parsing.
        args += ["-oX", "-", target]
        log.info("Running scan %s: %s", scan_id, " ".join(args))
        # Vuln/full scans can take a while; allow up to 30 min.
        res = run_command(args, timeout=1800)
        with self._lock:
            rec = self._scans[scan_id]
            rec["raw"] = res["stdout"][:200000]
            rec["finished"] = datetime.now(timezone.utc).isoformat()
            if res["ok"] or res["stdout"]:
                try:
                    parsed = self._parse_xml(res["stdout"])
                    rec["hosts"] = parsed["hosts"]
                    rec["summary"] = parsed["summary"]
                    rec["status"] = "completed"
                except ET.ParseError:
                    rec["status"] = "failed"
                    rec["error"] = res["stderr"] or "could not parse nmap output"
            else:
                rec["status"] = "failed"
                rec["error"] = res["stderr"] or "scan failed"
            self._active -= 1
        audit(rec["actor"], "scan_finish", target,
              f"status={rec['status']}", rec["status"])
        if rec["status"] == "completed":
            open_ports = rec["summary"].get("total_open_ports", 0)
            alert_manager.add(
                f"Scan completed on {target}: {open_ports} open ports across "
                f"{rec['summary'].get('hosts_up', 0)} host(s)",
                severity="info", source="scanner", meta={"scan_id": scan_id},
            )

    # ------------------------------------------------------------------ parsing
    @staticmethod
    def _parse_xml(xml_text: str) -> dict:
        root = ET.fromstring(xml_text)
        hosts = []
        total_open = 0
        for host in root.findall("host"):
            status = host.find("status")
            state = status.get("state") if status is not None else "unknown"
            addr = ""
            for a in host.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr")
                    break
            hostname = ""
            hn = host.find("hostnames/hostname")
            if hn is not None:
                hostname = hn.get("name", "")
            ports = []
            for p in host.findall("ports/port"):
                pstate = p.find("state")
                if pstate is None or pstate.get("state") != "open":
                    continue
                total_open += 1
                svc = p.find("service")
                ports.append({
                    "port": int(p.get("portid")),
                    "protocol": p.get("protocol"),
                    "service": svc.get("name") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                })
            # Collect any NSE vuln script findings on the host/ports.
            scripts = []
            for sc in host.findall(".//script"):
                scripts.append({"id": sc.get("id"),
                                "output": (sc.get("output") or "").strip()[:2000]})
            os_match = ""
            osm = host.find("os/osmatch")
            if osm is not None:
                os_match = osm.get("name", "")
            hosts.append({
                "address": addr,
                "hostname": hostname,
                "state": state,
                "os": os_match,
                "ports": ports,
                "scripts": scripts,
            })
        return {
            "hosts": hosts,
            "summary": {
                "hosts_up": sum(1 for h in hosts if h["state"] == "up"),
                "hosts_total": len(hosts),
                "total_open_ports": total_open,
            },
        }

    # -------------------------------------------------------------------- query
    def get(self, scan_id: str) -> dict | None:
        with self._lock:
            return self._scans.get(scan_id)

    def list(self, limit: int = 50) -> list[dict]:
        with self._lock:
            items = sorted(self._scans.values(), key=lambda x: x["started"], reverse=True)
        # Return lightweight rows (no raw XML) for the list view.
        return [{k: v for k, v in s.items() if k not in ("raw",)} for s in items[:limit]]

    def profiles(self) -> dict:
        return SCAN_PROFILES


scan_manager = ScanManager()
