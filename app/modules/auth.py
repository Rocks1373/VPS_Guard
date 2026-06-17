"""Simple, dependency-light authentication.

Stores a single (or few) user record(s) in ``data/users.json`` with a salted
PBKDF2-HMAC-SHA256 password hash. Seeds an initial admin account from config on
first run. Designed for a single-operator/self-hosted deployment.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from functools import wraps

from flask import session, jsonify, request

from app.config_loader import CONFIG, abspath
from app.modules.logger import audit

_STORE = abspath(CONFIG, "data/users.json")
_lock = threading.Lock()
_ITERATIONS = 200_000


def _hash_password(password: str, salt: str | None = None) -> dict:
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _ITERATIONS)
    return {"salt": salt, "hash": dk.hex(), "iterations": _ITERATIONS}


def _verify_password(password: str, record: dict) -> bool:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                             bytes.fromhex(record["salt"]), record.get("iterations", _ITERATIONS))
    return hmac.compare_digest(dk.hex(), record["hash"])


def _load() -> dict:
    if os.path.exists(_STORE):
        try:
            with open(_STORE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def _save(users: dict) -> None:
    os.makedirs(os.path.dirname(_STORE), exist_ok=True)
    with open(_STORE, "w", encoding="utf-8") as fh:
        json.dump(users, fh, indent=2)
    os.chmod(_STORE, 0o600)


def ensure_seed_user() -> None:
    """Create the default admin account if no users exist yet."""
    with _lock:
        users = _load()
        if users:
            return
        username = CONFIG["auth"]["username"]
        users[username] = {
            "username": username,
            **_hash_password(CONFIG["auth"]["default_password"]),
            "must_change": True,
        }
        _save(users)


def verify_login(username: str, password: str) -> bool:
    users = _load()
    rec = users.get(username)
    if not rec:
        return False
    return _verify_password(password, rec)


def change_password(username: str, new_password: str) -> bool:
    with _lock:
        users = _load()
        if username not in users:
            return False
        users[username].update(_hash_password(new_password))
        users[username]["must_change"] = False
        _save(users)
    audit(username, "change_password", username, "", "ok")
    return True


def must_change_password(username: str) -> bool:
    return _load().get(username, {}).get("must_change", False)


def login_required(fn):
    """Decorator enforcing an authenticated session for protected endpoints."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not CONFIG["auth"]["enabled"]:
            return fn(*args, **kwargs)
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "authentication required"}), 401
            from flask import redirect, url_for
            return redirect(url_for("login_page"))
        return fn(*args, **kwargs)
    return wrapper
