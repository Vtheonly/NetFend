#!/bin/bash
# ============================================================
# NetFend — legacy compatibility wrapper.
# The original 'main.sh' was a monolithic installer that also wrote
# ad-hoc scripts (net_watch/net_protect/net_reset/net_blacklist) into
# /usr/local/bin. Those behaviors are now provided safely by:
#   install.sh / uninstall.sh   (installation lifecycle)
#   net_defender.py CLI         (netfend --status/--doctor/--events/...)
# This wrapper keeps old muscle-memory working without the unsafe
# parts (e.g. net_reset's interface bouncing — see docs/audit.md RC-7).
# ============================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${1:-install}" in
  install)  exec bash "$SCRIPT_DIR/install.sh" "${@:2}" ;;
  uninstall) exec bash "$SCRIPT_DIR/uninstall.sh" "${@:2}" ;;
  *)
    cat <<'EOF'
NetFend installer (compatibility wrapper)

  ./main.sh install    -> runs install.sh (safe installer, supports --dry-run/--check)
  ./main.sh uninstall  -> runs uninstall.sh (complete removal, supports --keep-data)

Single entry (installed):
  sudo netfend         -> engine + dashboard in the foreground, Ctrl+C stops

Legacy commands map to the modern engine (installed as launchers):
  net_protect   -> sudo netfend            (same single entry)
  net_watch     -> netfend --status / dashboard http://127.0.0.1:8787
  net_reset     -> systemctl stop netfend  (NO interface bouncing anymore)
  net_blacklist -> netfend --blacklist
EOF
    ;;
esac
