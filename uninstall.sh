#!/bin/bash
# ============================================================
# NetFend — complete uninstaller
# Usage:
#   sudo ./uninstall.sh              # full removal incl. data
#   sudo ./uninstall.sh --keep-data  # keep /var/lib/netfend (events, registry)
# ============================================================
set -u

KEEP_DATA=0
[ "${1:-}" = "--keep-data" ] && KEEP_DATA=1

log() { echo "[netfend-uninstall] $*"; }

if [ "$(id -u)" != "0" ]; then
  echo "ERROR: run as root (sudo ./uninstall.sh)" >&2
  exit 1
fi

# 1) Stop and disable service
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files netfend.service >/dev/null 2>&1; then
  log "Stopping netfend service..."
  systemctl stop netfend.service 2>/dev/null || true
  systemctl disable netfend.service 2>/dev/null || true
  rm -f /etc/systemd/system/netfend.service
  systemctl daemon-reload
fi

# 2) Kill any stray engine process
pkill -f "/opt/netfend/net_defender.py" 2>/dev/null || true

# 3) Remove engine-owned kernel state (ONLY ours — ADR-003)
if command -v nft >/dev/null 2>&1; then
  log "Removing engine-owned nftables tables..."
  nft delete table inet netfend_filter 2>/dev/null || true
  nft delete table arp netfend_arp 2>/dev/null || true
fi

# 4) Remove static neighbor entries created by the engine.
#    The engine removes these on clean stop; this is the safety net.
#    We cannot identify individual permanent entries as ours, so we only
#    convert permanent entries on the default-route interface back to
#    dynamic — a conservative, connectivity-preserving operation.
IFACE=$(ip route 2>/dev/null | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
if [ -n "${IFACE:-}" ] && command -v ip >/dev/null 2>&1; then
  log "Releasing permanent neighbor entries on $IFACE (if any)..."
  ip -4 neigh show dev "$IFACE" 2>/dev/null | awk '/PERMANENT/ {print $1}' | while read -r ip_addr; do
    ip neigh del "$ip_addr" dev "$IFACE" 2>/dev/null || true
    # re-learn dynamically on next traffic
  done
fi

# 5) Remove files
log "Removing files..."
rm -f /usr/local/bin/netfend
rm -f /usr/local/bin/net_protect /usr/local/bin/net_reset \
      /usr/local/bin/net_watch /usr/local/bin/net_blacklist
rm -rf /opt/netfend
rm -rf /etc/netfend

# 6) Data (events, device registry, blacklist, token, logs)
if [ "$KEEP_DATA" = "1" ]; then
  log "Keeping /var/lib/netfend (--keep-data)"
else
  log "Removing /var/lib/netfend"
  rm -rf /var/lib/netfend
fi

log "NetFend fully removed. No engine-owned kernel state remains."
