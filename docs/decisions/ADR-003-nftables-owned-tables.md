# ADR-003 — Engine-owned nftables tables with validate-and-rollback

**Status:** Accepted 2026-10-15
**Context:** Legacy code used `arptables -F` (global flush — destroys user
rules, audit RC-4) and had no IP-layer firewall at all. Modern Linux
supersedes arptables with the nftables `arp` family.

**Decision:** All kernel rules live in two engine-owned tables:

- `table inet netfend_filter` — IP-layer input hardening: drop invalid,
  accept established/related, allow loopback, ICMP rate limiting, and
  rate-limited NEW connections (scan/SYN-flood resistance). Policy remains
  `accept` in the default profile (a `strict` profile with default-drop is
  opt-in) so legitimate services keep working.
- `table arp netfend_arp` — drop ARP replies claiming the gateway IP from
  a wrong MAC, and replies claiming our own IP from a foreign MAC.

Rules are applied via `nft -f` from a generated ruleset, then a
connectivity self-check runs (gateway ping + DNS resolution). On failure
the tables are deleted, a CRITICAL event is emitted, and a backoff timer
prevents tight retry loops. `nft delete table` on shutdown *only* touches
our tables. Every rule change is preceded by `nft -c` (check/dry-run)
validation.

**Consequences:** No interference with user/firewall-frontend rules; clean
uninstall; safe under crashes (systemd ExecStopPost cleanup + idempotent
start). Requires `nft` ≥ 0.9 and kernel nftables support — capability-
probed at startup with clear warnings when absent.
