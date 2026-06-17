"""Configuration loader for the Security Monitoring Dashboard.

Loads ``config/config.yaml`` and allows overrides via environment variables
prefixed with ``SECDASH_``. Nested keys are separated by ``_``.
Example: ``SECDASH_SERVER_PORT=8080`` overrides ``server.port``.
"""
from __future__ import annotations

import os
import copy
import yaml

# Repository root (two levels up from this file: app/ -> project root)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yaml")

_DEFAULTS = {
    "server": {"host": "0.0.0.0", "port": 5000, "secret_key": "change-me", "debug": False},
    "auth": {"enabled": True, "username": "admin", "default_password": "changeme",
             "session_timeout_minutes": 120},
    "monitoring": {"poll_interval": 5,
                   "track_states": ["ESTABLISHED", "SYN_SENT", "SYN_RECV", "TIME_WAIT"],
                   "connection_threshold": 100,
                   "sensitive_ports": [22, 3306, 5432, 6379, 27017, 9200]},
    "ids": {"fail2ban_enabled": True, "jails": []},
    "firewall": {"backend": "ufw", "enforce": False, "iptables_chain": "SECDASH_BLOCK"},
    "offensive": {"enabled": True, "require_authorization": True, "target_allowlist": [],
                  "target_denylist": ["169.254.169.254"], "nmap_path": "nmap",
                  "max_concurrent_scans": 2},
    "alerts": {"retention_days": 30, "webhook_url": "", "webhook_min_severity": "high"},
    "logging": {"level": "INFO", "app_log": "logs/app.log", "audit_log": "logs/audit.log",
                "alert_log": "logs/alerts.log", "max_bytes": 10485760, "backup_count": 5},
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _coerce(value: str):
    """Best-effort conversion of an env-var string to bool/int/float/str."""
    low = value.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _apply_env_overrides(cfg: dict) -> dict:
    for env_key, env_val in os.environ.items():
        if not env_key.startswith("SECDASH_"):
            continue
        path = env_key[len("SECDASH_"):].lower().split("_")
        node = cfg
        for part in path[:-1]:
            if part not in node or not isinstance(node[part], dict):
                node[part] = {}
            node = node[part]
        node[path[-1]] = _coerce(env_val)
    return cfg


def load_config() -> dict:
    cfg = copy.deepcopy(_DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            file_cfg = yaml.safe_load(fh) or {}
        cfg = _deep_merge(cfg, file_cfg)
    cfg = _apply_env_overrides(cfg)
    cfg["_base_dir"] = BASE_DIR
    return cfg


def abspath(cfg: dict, relative: str) -> str:
    """Resolve a config-relative path to an absolute path under the project root."""
    if os.path.isabs(relative):
        return relative
    return os.path.join(cfg["_base_dir"], relative)


CONFIG = load_config()
