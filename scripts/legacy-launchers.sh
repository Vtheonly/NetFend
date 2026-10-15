#!/bin/bash
# ============================================================
# NetFend legacy-compatible launchers (P-26).
#
# The owner's muscle memory is `net_protect` — one command, sudo,
# engine in the foreground. These shims keep that workflow but point
# at the MODERN engine (the legacy engine has been completely removed;
# docs/architecture/legacy-absorption-map.md records where its useful
# concepts now live. It must never be executed: it violated
# ADR-001/002 and crashed on stop — see docs/audit.md and report.md).
# ============================================================
set -euo pipefail

NETFEND="/usr/local/bin/netfend"   # symlink to /opt/netfend/net_defender.py

case "$(basename "$0")" in
  net_protect)
    # single entry: engine + dashboard in the foreground, Ctrl+C to stop
    exec sudo "$NETFEND" "$@"
    ;;
  net_reset)
    # safe stop: systemctl first, then a direct SIGTERM fallback.
    # The legacy net_reset bounced the interface (RC-7) — NEVER again.
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files netfend.service >/dev/null 2>&1; then
      sudo systemctl stop netfend.service && echo "[NetFend] Service stopped; engine-owned kernel state removed."
    elif pgrep -f "/opt/netfend/net_defender.py" >/dev/null 2>&1; then
      sudo pkill -TERM -f "/opt/netfend/net_defender.py"
      echo "[NetFend] Foreground engine stopped (clean signal; kernel state removed)."
    else
      echo "[NetFend] No running engine found."
    fi
    ;;
  net_watch)
    # live view: status snapshot + where the rich dashboard lives
    "$NETFEND" --status
    echo
    echo "[NetFend] Live dashboard: http://127.0.0.1:8787/  (localhost only)"
    echo "[NetFend] Event stream:  sudo journalctl -u netfend -f   or   netfend --events 20"
    ;;
  net_blacklist)
    exec "$NETFEND" --blacklist "$@"
    ;;
  *)
    echo "[NetFend] unknown launcher name: $0" >&2
    exit 1
    ;;
esac
