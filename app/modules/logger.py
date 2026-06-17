"""Centralised logging, audit trail and alert subsystem.

Provides:
  * ``get_logger()``       - rotating application logger
  * ``audit(...)``         - append a tamper-evident-ish audit line (who/what/when)
  * ``AlertManager``       - in-memory + on-disk alert store with severity levels,
                             optional webhook dispatch, and retention pruning.
"""
from __future__ import annotations

import os
import json
import time
import logging
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from collections import deque

from app.config_loader import CONFIG, abspath

_LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_loggers: dict[str, logging.Logger] = {}
_lock = threading.Lock()


def _ensure_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)


def get_logger(name: str = "secdash") -> logging.Logger:
    with _lock:
        if name in _loggers:
            return _loggers[name]
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, CONFIG["logging"]["level"].upper(), logging.INFO))
        logger.propagate = False
        log_path = abspath(CONFIG, CONFIG["logging"]["app_log"])
        _ensure_dir(log_path)
        handler = RotatingFileHandler(
            log_path,
            maxBytes=CONFIG["logging"]["max_bytes"],
            backupCount=CONFIG["logging"]["backup_count"],
        )
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        handler.setFormatter(fmt)
        logger.addHandler(handler)
        # Also echo to stderr for container / journald visibility
        stream = logging.StreamHandler()
        stream.setFormatter(fmt)
        logger.addHandler(stream)
        _loggers[name] = logger
        return logger


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit(actor: str, action: str, target: str = "", detail: str = "",
          result: str = "ok") -> None:
    """Append a structured audit record. Used for every security-relevant action
    (logins, scans, firewall changes) to maintain accountability."""
    path = abspath(CONFIG, CONFIG["logging"]["audit_log"])
    _ensure_dir(path)
    record = {
        "ts": _now_iso(),
        "actor": actor,
        "action": action,
        "target": target,
        "detail": detail,
        "result": result,
    }
    with _lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    get_logger("audit").info("%s %s %s -> %s", actor, action, target, result)


class AlertManager:
    """Stores alerts on disk (JSONL) and keeps a rolling in-memory window for
    fast dashboard queries. Dispatches high-severity alerts to a webhook."""

    def __init__(self, max_memory: int = 1000):
        self._alerts: deque = deque(maxlen=max_memory)
        self._path = abspath(CONFIG, CONFIG["logging"]["alert_log"])
        _ensure_dir(self._path)
        self._lock = threading.Lock()
        self._counter = 0
        self._load_recent()

    def _load_recent(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()[-self._alerts.maxlen:]
            for line in lines:
                line = line.strip()
                if line:
                    rec = json.loads(line)
                    self._alerts.append(rec)
                    self._counter = max(self._counter, rec.get("id", 0))
        except (OSError, json.JSONDecodeError):
            pass

    def add(self, message: str, severity: str = "info", source: str = "system",
            meta: dict | None = None) -> dict:
        severity = severity.lower()
        if severity not in _LEVELS:
            severity = "info"
        with self._lock:
            self._counter += 1
            alert = {
                "id": self._counter,
                "ts": _now_iso(),
                "severity": severity,
                "source": source,
                "message": message,
                "meta": meta or {},
                "acknowledged": False,
            }
            self._alerts.append(alert)
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(alert) + "\n")
        get_logger("alerts").log(
            logging.WARNING if _LEVELS[severity] >= 2 else logging.INFO,
            "[%s] %s (%s)", severity.upper(), message, source,
        )
        self._maybe_webhook(alert)
        return alert

    def _maybe_webhook(self, alert: dict) -> None:
        url = CONFIG["alerts"].get("webhook_url")
        if not url:
            return
        min_sev = CONFIG["alerts"].get("webhook_min_severity", "high")
        if _LEVELS.get(alert["severity"], 0) < _LEVELS.get(min_sev, 3):
            return
        # Fire-and-forget so we never block the request path.
        threading.Thread(target=self._post_webhook, args=(url, alert), daemon=True).start()

    @staticmethod
    def _post_webhook(url: str, alert: dict) -> None:
        try:
            import requests
            payload = {"text": f"[{alert['severity'].upper()}] {alert['message']} "
                               f"(source: {alert['source']}, {alert['ts']})"}
            requests.post(url, json=payload, timeout=5)
        except Exception as exc:  # noqa: BLE001 - never crash on webhook failure
            get_logger().warning("Webhook dispatch failed: %s", exc)

    def list(self, limit: int = 100, min_severity: str | None = None) -> list[dict]:
        items = list(self._alerts)[::-1]
        if min_severity:
            threshold = _LEVELS.get(min_severity.lower(), 0)
            items = [a for a in items if _LEVELS.get(a["severity"], 0) >= threshold]
        return items[:limit]

    def acknowledge(self, alert_id: int) -> bool:
        with self._lock:
            for a in self._alerts:
                if a["id"] == alert_id:
                    a["acknowledged"] = True
                    return True
        return False

    def stats(self) -> dict:
        counts = {k: 0 for k in _LEVELS}
        unack = 0
        for a in self._alerts:
            counts[a["severity"]] = counts.get(a["severity"], 0) + 1
            if not a["acknowledged"]:
                unack += 1
        return {"counts": counts, "total": len(self._alerts), "unacknowledged": unack}


# Singleton alert manager shared across the app
alert_manager = AlertManager()
