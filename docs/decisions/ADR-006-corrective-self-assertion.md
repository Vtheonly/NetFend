# ADR-006 — Corrective self-assertion (bounded active defense)

**Status:** Accepted 2026-10-16
**Context:** During a live gateway-spoofing incident (2026-10-15 field
report, `report.md`) the owner observed that the legacy engine "worked
better" than the modernized one. Root cause of the difference: the legacy
engine actively re-asserted ARP mappings while under attack, keeping the
victim reachable; the modernized engine was purely passive (kernel pin +
nftables) and — due to the P-18 firewall validation failure — even the
kernel-side protections were down that day, leaving nothing active.

The legacy approach is unacceptable as-is: counter-ARP blasts ran on a
timer at up to 600 packets/s (ADR-002 violation, self-inflicted airtime
DoS) and re-asserted the *gateway's* identity from the victim machine.

**Decision:** Add `netfend/services/active_defense.py` — a strictly
bounded corrective component that reacts **only** to confirmed threats
(`arp.gateway_spoof`, `arp.own_ip_conflict`):

1. **Kernel re-pin** — restore this host's neighbor-table view of the
   gateway to the trusted MAC (`ip neigh replace`). Zero packets.
2. **Self-assertion** — at most `arp.corrective_arp_max` (default 5, hard
   ceiling 10 regardless of config) gratuitous ARP replies that claim
   **only our own IP→MAC**. This directly counters the NetCut "cut the
   victim off" primitive, which poisons the *gateway's* cache about the
   victim.

Invariants (enforced by `tests/test_engine_safety.py` +
`tests/test_active_defense.py`):

- We **never** transmit a packet claiming another host's identity
  (ADR-001): `psrc`/`hwsrc` are always our own address.
- We **never** send on a timer (ADR-002): every burst is event-triggered
  by a confirmed detection, bounded in count, and gated by
  `arp.corrective_arp_cooldown_s` (default 60 s).
- `active_defense.py` is the **only** module permitted to call scapy
  send functions; every other service stays passive (AST-enforced).
- Frames are explicit L2 (`Ether`+`ARP`) — the legacy `send(ARP(...))`
  L3 crash class ("Missing 'dst' attribute") is structurally impossible.

**Consequences:** Under active poisoning the host re-asserts itself and
keeps its traffic flowing without becoming the noise source it fights.
Defense actions are visible as `defense.corrective_action` events and in
the dashboard's Local Network Attack Protection panel. The engine remains
idle-silent in steady state; an attacker who stops attacking stops the
response.

---

**Amendment (2026-10-16, P-28): sustained-attack mode.**

Field reality: attackers with bettercap/NetCut re-poison every 1–2 s. A
fixed 60 s cooldown meant one corrective burst followed by almost a
minute of silence while under continuous attack — precisely the window
in which the legacy engine "worked better". The amendment keeps every
invariant above and adds:

1. **Sustained mode** — a trigger arriving within
   `arp.corrective_sustain_window_s` (default 12 s) of the previous one
   marks the attack as sustained; the inter-burst interval then drops
   from the normal cooldown (60 s) to
   `arp.corrective_sustain_interval_s` (default 5 s). No timer, ever:
   bursts still fire only when fresh trigger evidence arrives.
2. **Airtime budget** — a sliding 60 s packet budget
   (`arp.corrective_packets_per_minute`, default 30, hard ceiling 60
   regardless of config) caps total corrective traffic even under
   maximum sustained pressure. Budget exhaustion skips the packet burst
   but never the (zero-packet) kernel re-pin.
3. **`arp.gateway_oscillation`** (a poison/anti-poison MAC trade-war)
   is now a trigger kind — a sustained fight is an active attack.
4. **Gateway unicast** — each burst now also sends up to `count` UNICAST
   replies to the gateway healing its cache about us (the exact cache
   NetCut poisons), in addition to the broadcast GARP healing the LAN.
   Still only our own identity (ADR-001).

Net effect: worst-case corrective traffic is ~0.5–1 packet/s under
continuous attack (budget-capped), and zero the moment the attack
stops. Evidence: `tests/test_active_defense.py` (sustained-mode,
interval, budget, re-pin-not-gated, unicast tests).
