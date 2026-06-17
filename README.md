# 🛡️ Security Monitoring Dashboard

A self-hosted, web-based **security monitoring and testing platform** for Ubuntu
Linux. It combines **defensive** monitoring (network visibility, intrusion
detection, firewall/IP blocking, alerting) with an **offensive** toolkit
(authorized Nmap-based scanning for bug-bounty / pentest work) behind a single,
clean dashboard.

It is built to **integrate proven open-source tools** — `nmap`, `fail2ban`,
`ufw`/`iptables`, and `psutil` — rather than reinventing them, so you get
battle-tested security capabilities with a friendly UI on top.

> ⚖️ **Ethics & legality:** The offensive tools are for systems you **own** or
> are **explicitly authorized** to test (e.g. an in-scope bug-bounty target).
> Unauthorized scanning is illegal in most jurisdictions. Every scan is logged
> to an audit trail. See [docs/OFFENSIVE.md](docs/OFFENSIVE.md).

---

## ✨ Features

### Defensive
- **Real-time network monitoring** — active connections, listening ports, top
  talkers, live throughput chart.
- **Intrusion detection** — `fail2ban` integration (view jails, banned IPs,
  ban/unban) plus a **built-in SSH brute-force watcher** fallback.
- **Automatic IP blocking** — single remote IPs exceeding a connection
  threshold raise a high-severity alert; one-click block from the UI.
- **Firewall management** — `ufw` or `iptables` backend with a persistent block
  list, plus a safe **DRY-RUN** mode for testing.
- **Alerts & logging** — severity-rated alerts, optional webhook (Slack/Discord),
  rotating app/audit/alert logs.

### Offensive / testing
- **Nmap-powered scans** — host discovery, quick/full port scans, service &
  version detection, OS fingerprinting, and NSE vulnerability scans.
- **Authorization gating** — explicit consent checkbox + allow/deny target
  lists + full audit logging keep usage ethical and accountable.
- **Parsed results** — open ports, services, versions and NSE findings rendered
  in the UI; raw XML retained.

### Platform
- Python **Flask** backend, vanilla JS + Chart.js frontend (no build step).
- Session-based auth with PBKDF2-hashed passwords.
- One-command Ubuntu setup script + systemd service.
- Clean separation of defensive vs offensive code and UI.

---

## 🚀 Quick Start (Ubuntu)

```bash
# 1. Get the code onto your Ubuntu host, then:
cd security_dashboard

# 2. Install everything (Python deps + nmap/fail2ban/ufw + systemd service)
sudo ./scripts/setup.sh --all
#    …or a minimal install (Python only, run manually):
./scripts/setup.sh

# 3. If you installed manually, start it:
source .venv/bin/activate
python run.py

# 4. Open the dashboard
#    http://localhost:5000   (or http://<server-ip>:5000)
#    Default login:  admin / changeme   ← CHANGE IMMEDIATELY
```

Full step-by-step instructions: **[docs/INSTALL.md](docs/INSTALL.md)**

---

## 📂 Project Structure

```
security_dashboard/
├── app/
│   ├── server.py              # Flask app: routes, auth, background poller
│   ├── config_loader.py       # YAML + env-var config loader
│   ├── modules/
│   │   ├── logger.py          # logging, audit trail, AlertManager
│   │   ├── utils.py           # safe subprocess + validation helpers
│   │   ├── auth.py            # PBKDF2 auth + login_required decorator
│   │   ├── network_monitor.py # connections + throughput + anomaly detection
│   │   ├── firewall.py        # ufw/iptables block management (+ DRY-RUN)
│   │   ├── ids.py             # fail2ban integration + SSH watcher fallback
│   │   ├── scanner.py         # Nmap offensive toolkit (authorization-gated)
│   │   └── system_status.py   # CPU/mem/disk/service health
│   ├── templates/             # login.html, dashboard.html
│   └── static/css,js          # UI styling + controller
├── config/
│   ├── config.yaml            # main configuration
│   └── fail2ban-sshd.local.example
├── scripts/
│   ├── setup.sh               # Ubuntu installer
│   └── security-dashboard.service.template
├── docs/
│   ├── INSTALL.md             # installation guide
│   ├── DEFENSIVE.md           # defensive operations guide
│   ├── OFFENSIVE.md           # bug-bounty / testing guide
│   └── BEST_PRACTICES.md      # hardening + example workflows
├── requirements.txt
├── run.py                     # entry point (python run.py)
└── README.md
```

---

## ⚙️ Configuration

All settings live in [`config/config.yaml`](config/config.yaml) and can be
overridden by environment variables prefixed `SECDASH_` (e.g.
`SECDASH_SERVER_PORT=8080`). Key options:

| Setting | Purpose |
|---|---|
| `firewall.enforce` | `false` = DRY-RUN (log only, safe). `true` = apply real firewall rules. |
| `firewall.backend` | `ufw` or `iptables`. |
| `offensive.enabled` | Master switch for the scanning toolkit. |
| `offensive.target_allowlist` | CIDRs/hosts you're allowed to scan (strongly recommended). |
| `offensive.target_denylist` | Targets that must never be scanned. |
| `monitoring.connection_threshold` | Per-IP connection count that triggers an alert. |
| `alerts.webhook_url` | Optional Slack/Discord/webhook for high-severity alerts. |

---

## 🔐 Privileges

Some features need elevated privileges on Linux:

| Feature | Requirement |
|---|---|
| Full connection/process visibility | root (or `CAP_NET_ADMIN`) |
| Firewall enforcement (ufw/iptables) | root |
| OS detection / SYN scans (nmap) | root |
| fail2ban control | root or `fail2ban` group |

Running via the provided **systemd service as root** unlocks all features. For
read-only monitoring you can run unprivileged (with reduced visibility).

---

## 📖 Documentation
- **[Installation guide](docs/INSTALL.md)**
- **[Defensive operations](docs/DEFENSIVE.md)**
- **[Offensive / bug-bounty testing](docs/OFFENSIVE.md)**
- **[Best practices & example workflows](docs/BEST_PRACTICES.md)**

---

## ⚠️ Disclaimer
This software is provided for **legitimate security monitoring and authorized
testing only**. You are solely responsible for complying with all applicable
laws and for obtaining proper authorization before scanning any system. The
authors assume no liability for misuse.

## License
MIT — see headers. Use responsibly.
