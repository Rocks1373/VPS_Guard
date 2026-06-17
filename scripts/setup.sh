#!/usr/bin/env bash
# ===========================================================================
# Security Monitoring Dashboard - Ubuntu setup / installation script
# ===========================================================================
# Tested on Ubuntu 20.04 / 22.04 / 24.04.
#
# Usage:
#   chmod +x scripts/setup.sh
#   ./scripts/setup.sh                 # install deps + python venv
#   sudo ./scripts/setup.sh --tools    # also install nmap, fail2ban, ufw
#   sudo ./scripts/setup.sh --service  # also install + enable systemd service
#   sudo ./scripts/setup.sh --all      # everything
# ===========================================================================
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
INSTALL_TOOLS=false
INSTALL_SERVICE=false
SERVICE_USER="${SUDO_USER:-$USER}"

for arg in "$@"; do
  case "$arg" in
    --tools)   INSTALL_TOOLS=true ;;
    --service) INSTALL_SERVICE=true ;;
    --all)     INSTALL_TOOLS=true; INSTALL_SERVICE=true ;;
    *) echo "Unknown option: $arg"; exit 1 ;;
  esac
done

c_green(){ printf "\033[32m%s\033[0m\n" "$1"; }
c_yellow(){ printf "\033[33m%s\033[0m\n" "$1"; }
c_red(){ printf "\033[31m%s\033[0m\n" "$1"; }

echo "==========================================================="
c_green " Security Monitoring Dashboard - Setup"
echo " Project: $PROJECT_DIR"
echo "==========================================================="

# --- 1. System packages ---------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
  c_green "[1/5] Installing base system packages (python3, venv, pip)…"
  if [ "$(id -u)" -eq 0 ]; then
    apt-get update -y
    apt-get install -y python3 python3-venv python3-pip
  else
    c_yellow "  (not root) attempting with sudo…"
    sudo apt-get update -y
    sudo apt-get install -y python3 python3-venv python3-pip
  fi
else
  c_yellow "[1/5] apt-get not found - skipping system package install. Ensure python3/venv exist."
fi

# --- 2. Security tools (optional) -----------------------------------------
if [ "$INSTALL_TOOLS" = true ]; then
  c_green "[2/5] Installing security tools (nmap, fail2ban, ufw)…"
  SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
  $SUDO apt-get install -y nmap fail2ban ufw
  $SUDO systemctl enable --now fail2ban || c_yellow "  could not enable fail2ban"
else
  c_yellow "[2/5] Skipping security tools install (run with --tools to include nmap/fail2ban/ufw)."
fi

# --- 3. Python virtualenv -------------------------------------------------
c_green "[3/5] Creating Python virtual environment…"
python3 -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$PROJECT_DIR/requirements.txt"

# --- 4. Directories & permissions -----------------------------------------
c_green "[4/5] Preparing data/log directories…"
mkdir -p "$PROJECT_DIR/logs" "$PROJECT_DIR/data"
chmod 750 "$PROJECT_DIR/data" || true

# --- 5. systemd service (optional) ----------------------------------------
if [ "$INSTALL_SERVICE" = true ]; then
  if [ "$(id -u)" -ne 0 ]; then
    c_red "[5/5] --service requires root. Re-run with sudo."
    exit 1
  fi
  c_green "[5/5] Installing systemd service…"
  SERVICE_FILE=/etc/systemd/system/security-dashboard.service
  sed -e "s|{{PROJECT_DIR}}|$PROJECT_DIR|g" \
      -e "s|{{USER}}|$SERVICE_USER|g" \
      "$PROJECT_DIR/scripts/security-dashboard.service.template" > "$SERVICE_FILE"
  systemctl daemon-reload
  systemctl enable security-dashboard.service
  systemctl restart security-dashboard.service
  c_green "  Service installed & started: systemctl status security-dashboard"
else
  c_yellow "[5/5] Skipping systemd service (run with --service to install)."
fi

echo "==========================================================="
c_green " Setup complete!"
echo ""
echo " To start the dashboard manually:"
echo "   source $VENV_DIR/bin/activate"
echo "   python run.py"
echo ""
echo " Then open: http://localhost:5000"
echo " Default login: admin / changeme  (CHANGE IT IMMEDIATELY)"
echo ""
c_yellow " NOTE: For full privileges (firewall enforcement, OS detection, all"
c_yellow " connection visibility) run the service as root or via systemd."
echo "==========================================================="
