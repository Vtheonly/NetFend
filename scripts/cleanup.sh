#!/bin/bash
# NetFend cleanup helper — run as systemd ExecStopPost.
# Removes ONLY engine-owned kernel state (never foreign rules):
#  - nftables tables netfend_filter / netfend_arp
#  - static neighbor entries created by the engine (best effort: flush of
#    permanent entries is done by the engine itself before exit; this is a
#    crash-path safety net that only deletes our nftables tables, because
#    permanent neighbor entries cannot be identified as ours post-crash).
set -u

command -v nft >/dev/null 2>&1 || exit 0

nft delete table inet netfend_filter 2>/dev/null || true
nft delete table arp netfend_arp 2>/dev/null || true

exit 0
