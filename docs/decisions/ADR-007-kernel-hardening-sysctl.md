# ADR-007 — Engine-owned kernel hardening (sysctl) with restore contract

**Status:** Accepted 2026-10-16
**Context:** The updated threat model (2026-10-16) assumes a dedicated
adversary on the LAN and possibly a compromised gateway. Kernel defaults
trust L3 metadata that this adversary controls:

- `accept_redirects=1` lets ICMP redirects (bettercap module) move our
  routes to an attacker next hop — a silent MITM that survives ARP fixes.
- `accept_source_route=1` honors attacker-defined source routes.
- `rp_filter=0/2` (loose) accepts spoofed source addresses, enabling
  reflection and bypass of address-based trust.
- broadcast ICMP replies are a cheap LAN mapping primitive.

The engine already owned nftables tables and static neighbor entries
(ADR-003); kernel network parameters were left at distribution defaults.

**Decision:** Add `netfend/services/hardening.py` (`KernelHardener`):

1. On engine start (root, dry-run off, `hardening.enabled`), enforce:
   `accept_redirects=0` (all/default, v4+v6), `secure_redirects=0`,
   `accept_source_route=0`, `send_redirects=0`,
   `icmp_echo_ignore_broadcasts=1`, and `rp_filter` per
   `hardening.rp_filter` (`strict`=1 default / `loose`=2 / `preserve`).
2. Writes go directly to `/proc/sys` (stdlib file I/O — no `sysctl`
   binary, no subprocess, no shell). Reads/writes are fail-soft: a
   kernel without a knob records a `skipped` entry, never an error.
3. **Restore contract:** the pre-change values are persisted to
   `DATA_DIR/hardening_state.json` BEFORE any write; engine stop
   restores them (unless `hardening.restore_on_stop=false`). A stale
   state file from a crashed run is restored first (crash recovery) so
   saved originals are always the true pre-hardening values.
4. The restore path refuses any state entry outside `net/…` or
   containing `..` — the state file must never become an arbitrary
   file-write primitive.
5. `accept_ra` (IPv6) is deliberately NOT owned by this module — the
   IPv6 guard (T-32) owns it, so each module restores exactly what it
   changed.

**Consequences:** The host ignores ICMP redirect and source-route
manipulation at the kernel level even when the attacker is the gateway
itself. Multi-homed/VPN hosts with asymmetric routing must set
`hardening.rp_filter=loose` or `preserve` (strict rp_filter drops
legitimate asymmetrically-routed packets — documented in README and
AGENTS.md §5). All changes are engine-owned and observable
(`hardening.applied` / `hardening.restored` events; `status()` for the
doctor and dashboard). Evidence: `tests/test_hardening.py`.
