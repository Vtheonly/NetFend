# ADR-005 — Event-driven architecture, optional dependencies, pure detection logic

**Status:** Accepted 2026-10-15
**Context:** The legacy engine was a monolith: blocking startup scans
(audit RC-12), mandatory scapy/colorama imports, per-packet disk writes
(RC-9), and one-shot network identity (RC-5).

**Decision:**

1. **Event bus at the core.** `EventStore` is the single sink for
   `SecurityEvent`s (kind, severity, confidence, evidence, source). All
   guards (ARP/DHCP/DNS/Wi-Fi/flood/health) emit events; the CLI, logs and
   dashboard are all views over the same store. Events persist as rotating
   JSONL (`events.jsonl`, size-capped).
2. **Detection is pure.** Each guard splits into (a) an adapter that turns
   raw observations (scapy packets, `ip`/`iw`/`nmcli` output, /proc reads)
   into plain dicts, and (b) pure `evaluate_*(state, observation)`
   functions with no I/O. Tests exercise (b) without root, network, or
   scapy installed.
3. **Every dependency is capability-probed.** `Capabilities` records at
   startup which of scapy/colorama/psutil/nft/iw/nmcli/systemd exist.
   Missing capabilities degrade features with WARNING events — never
   crashes (verified: the reference test environment has no scapy on the
   default interpreter and the engine still boots in dry-run mode).
4. **Network change detection without polling storms:** a `ip monitor
   route link neigh` subprocess feeds a parser (netlink without pyroute2
   dependency); NetworkManager state is read opportunistically. On any
   change the engine re-baselines identity and re-applies protections with
   ADR-003 validation.
5. **Interruptible everything.** All loops wait on `threading.Event` with
   timeouts; systemd stop completes in < 2 s.

**Consequences:** The engine runs (degraded, clearly flagged) on stripped
systems; tests are fast and hermetic; new guards plug in by emitting
events.
