# ADR-002 — Idle-silent defense (no timed packet transmission)

**Status:** Accepted 2026-10-15
**Context:** Legacy mitigation loop sent ARP frames every 0.05–1 s
permanently (audit RC-1). Wi-Fi airtime is shared; the defender was the
biggest ARP talker on the network.

**Decision:** The steady-state defense generates **zero** packets.
Protection is kernel-resident: static neighbor entries (`ip neigh ...
nud permanent`) and nftables rules evaluate at line rate in the kernel
with no per-packet userspace cost. Userspace reacts only to events
(netlink, sniffed hostile packets, threshold breaches). Any transmitted
packet (e.g., a single corrective gratuitous ARP *after a confirmed
poisoning of this host's cache*) is event-triggered, bounded (small
count), and rate-limited.

**Consequences:** Near-zero idle CPU/airtime overhead; behavior no longer
mimics the attacks it defends against. Static neighbor entry means a
genuine router replacement requires re-baselining — handled by network
change monitoring (ADR-005) plus a confidence-gated "gateway identity
changed" workflow rather than a hardcoded permanent pin that survives
reality changes.
