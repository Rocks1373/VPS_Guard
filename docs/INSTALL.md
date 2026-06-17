# Installation Guide (Ubuntu)

This guide covers installing the Security Monitoring Dashboard on Ubuntu
20.04 / 22.04 / 24.04. It works on a VPS, a home server, or a laptop.

---

## 1. Prerequisites

- Ubuntu 20.04+ (Debian-based distros should also work)
- A user with `sudo` privileges
- Outbound internet access to install packages

The dashboard integrates these tools (installed automatically with `--tools`):
- **nmap** — scanning engine for the offensive toolkit
- **fail2ban** — intrusion detection / automated banning
- **ufw** — uncomplicated firewall (or use `iptables`)

---

## 2. Get the code

Copy the `security_dashboard/` directory to your server, e.g. via `scp`, `git`,
or the download button in this UI:

```bash
# example with scp from your laptop
scp -r security_dashboard user@your-server:/opt/

# on the server
cd /opt/security_dashboard
```

---

## 3. Automated install (recommended)

The setup script handles system packages, a Python virtual environment, and
(optionally) the security tools and a systemd service.

```bash
chmod +x scripts/setup.sh

# Option A — full install: python deps + nmap/fail2ban/ufw + systemd service
sudo ./scripts/setup.sh --all

# Option B — tools but no service (you run it manually)
sudo ./scripts/setup.sh --tools

# Option C — minimal: just the Python environment
./scripts/setup.sh
```

What each flag does:
| Flag | Action |
|---|---|
| (none) | Installs python3/venv/pip + creates `.venv` + installs Python requirements |
| `--tools` | Also installs and enables `nmap`, `fail2ban`, `ufw` |
| `--service` | Also installs + enables a systemd service (`security-dashboard`) |
| `--all` | `--tools` + `--service` |

---

## 4. Manual install (alternative)

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nmap fail2ban ufw

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python run.py          # starts on http://0.0.0.0:5000
```

---

## 5. First login

1. Open `http://<server-ip>:5000` (or `http://localhost:5000` locally).
2. Log in with the default credentials: **`admin` / `changeme`**.
3. **Immediately change the password** — the dashboard offers a change-password
   action; or edit `config/config.yaml` (`auth.default_password`) **before**
   first launch and delete `data/users.json` to re-seed.

> The password is stored as a salted PBKDF2-SHA256 hash in `data/users.json`
> (file mode `600`).

---

## 6. Configure

Edit [`config/config.yaml`](../config/config.yaml). At minimum, review:

```yaml
server:
  secret_key: "<set a long random value>"   # or SECDASH_SERVER_SECRET_KEY

firewall:
  backend: "ufw"        # or "iptables"
  enforce: false        # set true to apply REAL firewall rules

offensive:
  enabled: true
  target_allowlist: ["192.168.1.0/24", "203.0.113.10"]   # YOUR assets/targets
```

Generate a strong secret key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Restart after config changes (`systemctl restart security-dashboard` or restart
`python run.py`).

---

## 7. Enable fail2ban (recommended for defense)

```bash
sudo cp config/fail2ban-sshd.local.example /etc/fail2ban/jail.local
sudo systemctl restart fail2ban
sudo fail2ban-client status            # verify jails
```

The dashboard auto-detects active jails under **IDS / fail2ban**.

---

## 8. Enable the firewall

```bash
sudo ufw allow OpenSSH          # don't lock yourself out!
sudo ufw allow 5000/tcp         # dashboard (restrict to your IP if possible)
sudo ufw enable
```

Then set `firewall.enforce: true` in `config.yaml` so the dashboard's block
buttons apply real `ufw` rules.

---

## 9. Run as a service (production)

If you used `--service`, the dashboard runs under systemd via gunicorn:

```bash
sudo systemctl status security-dashboard
sudo systemctl restart security-dashboard
sudo journalctl -u security-dashboard -f      # live logs
```

The service runs with a single worker + threads so the in-memory monitoring
state stays consistent. To run as root (full features), the template already
sets the invoking user — edit `User=` in
`/etc/systemd/system/security-dashboard.service` to `root` if desired, then
`sudo systemctl daemon-reload && sudo systemctl restart security-dashboard`.

---

## 10. Secure remote access

The dashboard speaks plain HTTP. For remote use, **put it behind HTTPS**:

- **Recommended:** reverse-proxy with nginx + Let's Encrypt (TLS termination),
  proxy to `127.0.0.1:5000`, and restrict by IP / VPN.
- **Quick & private:** access over an SSH tunnel:
  ```bash
  ssh -L 5000:localhost:5000 user@your-server
  # then browse http://localhost:5000 on your laptop
  ```

Never expose port 5000 directly to the internet without TLS + authentication +
IP allow-listing.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Access denied reading connections" in logs | Run as root / via systemd for full visibility. |
| Firewall blocks don't apply | Set `firewall.enforce: true` and run as root. |
| `nmap is not installed` | `sudo apt-get install nmap` or run setup with `--tools`. |
| IDS shows "fail2ban not reachable" | Install & start fail2ban; the built-in SSH watcher still runs. |
| Can't log in | Delete `data/users.json` to re-seed from config, then restart. |
| Port 5000 in use | Change `server.port` in config or `SECDASH_SERVER_PORT=8080`. |
