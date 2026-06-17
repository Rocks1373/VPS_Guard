"""Security Monitoring Dashboard - Flask application.

Run with:  python -m app.server     (from the project root)
or via the systemd unit / setup script described in docs/.
"""
from __future__ import annotations

import os
import threading
import time
from datetime import timedelta

from flask import (Flask, render_template, request, jsonify, session,
                   redirect, url_for)

from app.config_loader import CONFIG, abspath
from app.modules.logger import get_logger, audit, alert_manager
from app.modules import auth
from app.modules.network_monitor import network_monitor
from app.modules.firewall import firewall_manager
from app.modules.ids import ids_manager
from app.modules.scanner import scan_manager
from app.modules import system_status

log = get_logger()

BASE_DIR = CONFIG["_base_dir"]
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "app", "templates"),
    static_folder=os.path.join(BASE_DIR, "app", "static"),
)
app.secret_key = CONFIG["server"]["secret_key"]
app.permanent_session_lifetime = timedelta(minutes=CONFIG["auth"]["session_timeout_minutes"])

auth.ensure_seed_user()

# --------------------------------------------------------------------------- #
# Background collector thread                                                  #
# --------------------------------------------------------------------------- #
_poller_started = False
_poller_lock = threading.Lock()


def _background_poller() -> None:
    interval = CONFIG["monitoring"]["poll_interval"]
    log.info("Background poller started (interval=%ss)", interval)
    while True:
        try:
            network_monitor.collect()
            ids_manager.collect()
        except Exception as exc:  # noqa: BLE001 keep the loop alive
            log.exception("poller error: %s", exc)
        time.sleep(interval)


def start_poller() -> None:
    global _poller_started
    with _poller_lock:
        if _poller_started:
            return
        t = threading.Thread(target=_background_poller, daemon=True)
        t.start()
        _poller_started = True


# --------------------------------------------------------------------------- #
# Auth routes                                                                  #
# --------------------------------------------------------------------------- #
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_template("login.html")
    data = request.form if request.form else (request.get_json(silent=True) or {})
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if auth.verify_login(username, password):
        session.permanent = True
        session["user"] = username
        audit(username, "login", "", "", "ok")
        return jsonify({"ok": True, "must_change": auth.must_change_password(username)})
    audit(username or "?", "login", "", "", "failed")
    alert_manager.add(f"Failed dashboard login for '{username}' "
                      f"from {request.remote_addr}", severity="medium", source="auth")
    return jsonify({"ok": False, "error": "invalid credentials"}), 401


@app.route("/logout")
def logout():
    user = session.pop("user", None)
    if user:
        audit(user, "logout", "", "", "ok")
    return redirect(url_for("login_page"))


@app.route("/api/change_password", methods=["POST"])
@auth.login_required
def api_change_password():
    data = request.get_json(silent=True) or {}
    new = data.get("new_password") or ""
    if len(new) < 8:
        return jsonify({"ok": False, "error": "password must be at least 8 characters"}), 400
    auth.change_password(session["user"], new)
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
# Page routes                                                                  #
# --------------------------------------------------------------------------- #
@app.route("/")
@auth.login_required
def index():
    return render_template("dashboard.html",
                           username=session.get("user", ""),
                           offensive_enabled=CONFIG["offensive"]["enabled"])


# --------------------------------------------------------------------------- #
# Defensive API                                                                #
# --------------------------------------------------------------------------- #
@app.route("/api/overview")
@auth.login_required
def api_overview():
    net = network_monitor.snapshot()
    return jsonify({
        "ok": True,
        "system": system_status.get_status(),
        "network": {
            "established_count": net["established_count"],
            "listening_count": net["listening_count"],
            "total_count": net["total_count"],
            "current_rate": net["current_rate"],
            "top_talkers": net["top_talkers"],
        },
        "firewall": firewall_manager.status(),
        "ids": ids_manager.snapshot(),
        "alerts": alert_manager.stats(),
        "blocked_count": len(firewall_manager.list_blocked()),
    })


@app.route("/api/connections")
@auth.login_required
def api_connections():
    return jsonify({"ok": True, **network_monitor.snapshot()})


@app.route("/api/firewall/status")
@auth.login_required
def api_fw_status():
    return jsonify({"ok": True, "status": firewall_manager.status(),
                    "blocked": firewall_manager.list_blocked()})


@app.route("/api/firewall/block", methods=["POST"])
@auth.login_required
def api_fw_block():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    reason = (data.get("reason") or "").strip()
    res = firewall_manager.block_ip(ip, reason, actor=session.get("user", "user"))
    return jsonify(res), (200 if res.get("ok") else 400)


@app.route("/api/firewall/unblock", methods=["POST"])
@auth.login_required
def api_fw_unblock():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    res = firewall_manager.unblock_ip(ip, actor=session.get("user", "user"))
    return jsonify(res), (200 if res.get("ok") else 400)


@app.route("/api/ids/status")
@auth.login_required
def api_ids_status():
    return jsonify({"ok": True, **ids_manager.snapshot()})


@app.route("/api/ids/ban", methods=["POST"])
@auth.login_required
def api_ids_ban():
    data = request.get_json(silent=True) or {}
    res = ids_manager.ban(data.get("jail", ""), data.get("ip", ""))
    audit(session.get("user", "user"), "ids_ban", data.get("ip", ""),
          data.get("jail", ""), "ok" if res["ok"] else "failed")
    return jsonify(res)


@app.route("/api/ids/unban", methods=["POST"])
@auth.login_required
def api_ids_unban():
    data = request.get_json(silent=True) or {}
    res = ids_manager.unban(data.get("jail", ""), data.get("ip", ""))
    audit(session.get("user", "user"), "ids_unban", data.get("ip", ""),
          data.get("jail", ""), "ok" if res["ok"] else "failed")
    return jsonify(res)


# --------------------------------------------------------------------------- #
# Alerts API                                                                   #
# --------------------------------------------------------------------------- #
@app.route("/api/alerts")
@auth.login_required
def api_alerts():
    limit = int(request.args.get("limit", 100))
    min_sev = request.args.get("min_severity")
    return jsonify({"ok": True, "alerts": alert_manager.list(limit, min_sev),
                    "stats": alert_manager.stats()})


@app.route("/api/alerts/ack", methods=["POST"])
@auth.login_required
def api_alerts_ack():
    data = request.get_json(silent=True) or {}
    ok = alert_manager.acknowledge(int(data.get("id", 0)))
    return jsonify({"ok": ok})


# --------------------------------------------------------------------------- #
# Offensive API                                                                #
# --------------------------------------------------------------------------- #
def _offensive_guard():
    if not CONFIG["offensive"]["enabled"]:
        return jsonify({"ok": False, "error": "offensive toolkit disabled"}), 403
    return None


@app.route("/api/scan/profiles")
@auth.login_required
def api_scan_profiles():
    guard = _offensive_guard()
    if guard:
        return guard
    profiles = [{"key": k, **v} for k, v in scan_manager.profiles().items()]
    return jsonify({"ok": True, "profiles": profiles,
                    "allowlist": CONFIG["offensive"]["target_allowlist"],
                    "require_authorization": CONFIG["offensive"]["require_authorization"]})


@app.route("/api/scan/start", methods=["POST"])
@auth.login_required
def api_scan_start():
    guard = _offensive_guard()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    res = scan_manager.launch(
        target=(data.get("target") or "").strip(),
        profile=(data.get("profile") or "").strip(),
        ports=(data.get("ports") or "").strip(),
        authorized=bool(data.get("authorized")),
        actor=session.get("user", "user"),
    )
    return jsonify(res), (200 if res.get("ok") else 400)


@app.route("/api/scan/list")
@auth.login_required
def api_scan_list():
    guard = _offensive_guard()
    if guard:
        return guard
    return jsonify({"ok": True, "scans": scan_manager.list()})


@app.route("/api/scan/<scan_id>")
@auth.login_required
def api_scan_detail(scan_id):
    guard = _offensive_guard()
    if guard:
        return guard
    rec = scan_manager.get(scan_id)
    if not rec:
        return jsonify({"ok": False, "error": "scan not found"}), 404
    return jsonify({"ok": True, "scan": rec})


@app.route("/api/health")
def api_health():
    return jsonify({"ok": True, "service": "security-dashboard", "ts": time.time()})


# Start the poller as soon as the module is imported (works under flask run,
# gunicorn, and __main__).
start_poller()


def main():
    host = CONFIG["server"]["host"]
    port = int(CONFIG["server"]["port"])
    debug = bool(CONFIG["server"]["debug"])
    log.info("Starting Security Dashboard on %s:%s (debug=%s)", host, port, debug)
    app.run(host=host, port=port, debug=debug, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
