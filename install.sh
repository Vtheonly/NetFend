#!/bin/bash
# ============================================================
# NetFend — installer (safe, idempotent, with rollback)
# Usage:
#   sudo ./install.sh              # full install
#   ./install.sh --dry-run         # show what would happen
#   ./install.sh --check           # dependency/self test only
# Options:
#   --no-service   skip systemd service installation
#   --data-dir DIR custom state directory
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/netfend"
DATA_DIR="/var/lib/netfend"
CONFIG_DIR="/etc/netfend"
UNIT_SRC="$SCRIPT_DIR/systemd/netfend.service"
UNIT_DST="/etc/systemd/system/netfend.service"
CLI_SRC="$SCRIPT_DIR/net_defender.py"
CLI_LINK="/usr/local/bin/netfend"

DRY_RUN=0
CHECK_ONLY=0
NO_SERVICE=0
ROLLBACK_MARKER=()

log()  { echo "[netfend-install] $*"; }
warn() { echo "[netfend-install] WARNING: $*" >&2; }
die()  { echo "[netfend-install] ERROR: $*" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --dry-run)    DRY_RUN=1 ;;
    --check)      CHECK_ONLY=1 ;;
    --no-service) NO_SERVICE=1 ;;
    --data-dir)   shift_next=1 ;;
    *) if [ "${shift_next:-0}" = "1" ]; then DATA_DIR="$arg"; shift_next=0; fi ;;
  esac
done

run() {
  if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

# ---------------------------------------------------------------- checks
check_environment() {
  log "Checking environment..."

  [ "$(id -u)" = "0" ] || die "must run as root (try: sudo ./install.sh)"

  python3 --version >/dev/null 2>&1 || die "python3 not found"
  log "  python3: $(python3 --version 2>&1)"

  for tool in ip ping; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool missing: $tool"
  done
  log "  iproute2 + ping: OK"

  # Optional capabilities (warn only — engine degrades gracefully)
  for tool in nft iw nmcli; do
    if command -v "$tool" >/dev/null 2>&1; then
      log "  $tool: present"
    else
      warn "optional tool missing: $tool (related protection will be disabled with a clear warning)"
    fi
  done

  python3 - <<'PYEOF' || die "python dependencies check failed"
try:
    import json, http.server, threading, subprocess, collections, dataclasses
    print("  python stdlib: OK")
except ImportError as e:
    raise SystemExit(f"stdlib import failed: {e}")
PYEOF

  # Optional scapy
  if python3 -c "import scapy" >/dev/null 2>&1; then
    log "  scapy: present"
  else
    warn "scapy not installed — ARP/DHCP packet inspection will be disabled."
    warn "  install with: sudo apt-get install python3-scapy  (or: sudo pip3 install scapy)"
  fi

  # nftables kernel support
  if command -v nft >/dev/null 2>&1; then
    if nft list tables >/dev/null 2>&1; then
      log "  nftables kernel support: OK"
    else
      warn "nft present but kernel tables not listable (permissions?) — firewall enforcement may fail"
    fi
  fi

  log "Environment check complete."
}

# ---------------------------------------------------------------- install
install_files() {
  log "Installing engine to $INSTALL_DIR ..."
  run mkdir -p "$INSTALL_DIR"
  run cp -r "$SCRIPT_DIR/netfend" "$INSTALL_DIR/"
  run cp "$CLI_SRC" "$INSTALL_DIR/net_defender.py"
  run chmod 755 "$INSTALL_DIR/net_defender.py"
  if [ -d "$SCRIPT_DIR/netfend/dashboard" ]; then
    run chmod -R a+rX "$INSTALL_DIR/netfend/dashboard"
  fi
  run mkdir -p "$DATA_DIR"
  run chmod 700 "$DATA_DIR"
  run mkdir -p "$CONFIG_DIR"
  ROLLBACK_MARKER+=("$INSTALL_DIR")

  if [ ! -f "$CONFIG_DIR/config.json" ]; then
    if [ -f "$SCRIPT_DIR/config.example.json" ]; then
      run cp "$SCRIPT_DIR/config.example.json" "$CONFIG_DIR/config.json"
    else
      log "No config file installed (engine defaults will be used)."
    fi
  else
    log "Existing config preserved at $CONFIG_DIR/config.json"
  fi
}

install_service() {
  if [ "$NO_SERVICE" = "1" ]; then
    log "Skipping systemd service (--no-service)."
    return
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found — skipping service install (engine can run manually: sudo $INSTALL_DIR/net_defender.py)"
    return
  fi
  log "Installing systemd service..."
  run cp "$UNIT_SRC" "$UNIT_DST"
  run cp "$SCRIPT_DIR/scripts/cleanup.sh" "$INSTALL_DIR/scripts/cleanup.sh" 2>/dev/null || {
    run mkdir -p "$INSTALL_DIR/scripts"
    run cp "$SCRIPT_DIR/scripts/cleanup.sh" "$INSTALL_DIR/scripts/cleanup.sh"
  }
  run chmod 755 "$INSTALL_DIR/scripts/cleanup.sh"
  run systemctl daemon-reload
  run systemctl enable netfend.service
  ROLLBACK_MARKER+=("$UNIT_DST")
}

start_and_verify() {
  if [ "$NO_SERVICE" = "1" ] || ! command -v systemctl >/dev/null 2>&1; then
    return
  fi
  log "Starting service and verifying..."
  if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] systemctl restart netfend && sleep 3 && systemctl is-active netfend"
    return
  fi
  systemctl restart netfend.service
  sleep 3
  if systemctl is-active --quiet netfend.service; then
    log "Service is ACTIVE."
  else
    # --- rollback on failed start (never leave a broken install) ---
    log "Service failed to start — rolling back."
    journalctl -u netfend.service -n 30 --no-pager || true
    systemctl stop netfend.service 2>/dev/null || true
    systemctl disable netfend.service 2>/dev/null || true
    rm -f "$UNIT_DST"
    systemctl daemon-reload
    die "installation rolled back (see journal output above)"
  fi
}

# ---------------------------------------------------------------- rollback
rollback() {
  warn "rolling back installation..."
  for m in "${ROLLBACK_MARKER[@]:-}"; do
    [ -n "$m" ] && rm -rf "$m"
  done
  rm -f "$UNIT_DST" "$CLI_LINK"
  systemctl daemon-reload 2>/dev/null || true
}

# ---------------------------------------------------------------- main
main() {
  check_environment
  if [ "$CHECK_ONLY" = "1" ]; then
    log "--check complete."
    exit 0
  fi

  install_files

  # CLI symlink
  run ln -sf "$INSTALL_DIR/net_defender.py" "$CLI_LINK"

  # dashboard token (created by engine on first start if absent)

  install_service
  start_and_verify

  echo
  echo "  ================================================"
  echo "   NetFend installation complete"
  echo "  ================================================"
  echo "   CLI:            sudo netfend --status"
  echo "                   sudo netfend --doctor"
  echo "                   sudo netfend --events 20"
  echo "   Service:        systemctl status netfend"
  echo "   Dashboard:      http://127.0.0.1:8787/  (localhost only)"
  echo "   Token file:     $DATA_DIR/dashboard.token (chmod 600)"
  echo "   Config:         $CONFIG_DIR/config.json"
  echo "   Uninstall:      sudo ./uninstall.sh"
  echo "  ================================================"
}

trap 'rollback' ERR
main
