# ADR-008 — IPv6 RA guard (mitm6 / rogue-SLAAC vector)

**Status:** Accepted 2026-10-16
**Context:** Linux attackers pivot to IPv6 when IPv4 ARP is defended.
mitm6 and custom Scapy tools spam Router Advertisements (or answer
router solicitations) so the attacker's link-local address becomes the
victim's IPv6 default gateway, then win DHCPv6/DNS — full MITM on a
protocol the IPv4 defenses never watch. A compromised router can push
the same outcome through legitimate-looking RAs.

**Decision:** Add `netfend/services/ipv6_guard.py` with a defense split
by network reality:

1. **Suppression (v4-only networks — `ipv6.ra_guard`, default `auto`):**
   when no IPv6 default route exists, set `accept_ra = 0`
   (all/default/interface) and drop ICMPv6 router advertisements in the
   `netfend_filter` table at line rate. This is lossless on a v4-only
   LAN (no legitimate IPv6 to break) and closes the vector completely.
   Enforcement reuses the KernelHardener save/restore/crash-recovery
   contract (ADR-007) with a dedicated `ipv6_state.json` — each module
   restores exactly what it changed.
2. **Detection (IPv6 in use):** suppressing RAs would cut our own
   connectivity, so the guard instead sniffs RAs and flags more than
   `ipv6.ra_conflict_max_sources` distinct router sources inside the
   window as `ipv6.ra_conflict` (critical) — the rogue-RA/mitm6
   signature — feeding threat intel with the RA sender's MAC.
3. **Unknown routing state fails open for connectivity** (`auto` mode
   never suppresses when `ip -6 route` cannot be read); users on a
   known v4-only network can force suppression with
   `ipv6.ra_guard: "on"`.

Firewall ruleset changes (full + basic variants): ICMPv6
`nd-router-advert` drop when the guard is active, and ICMP redirect
drops (v4 `redirect`, v6 `nd-redirect`) ALWAYS — the redirect is the
gateway-grade route-hijack vector and is never legitimate for a
client; sysctl (ADR-007) already disables processing, the nft drop is
line-rate belt-and-braces. The RA drop is ordered BEFORE the strict
profile's blanket `icmpv6 accept` so even default-drop mode never
accepts rogue RAs.

**Consequences:** On typical v4-only home LANs the mitm6 vector is
closed at two independent layers. AF_PACKET sniffers observe frames
before netfilter input drops, so RA-conflict detection still works
while suppressing. Networks that legitimately use SLAAC IPv6 keep
connectivity and gain conflict detection instead. Not claimed (AGENTS
rule: never claim what the position cannot provide): DHCPv6 option
*content* inspection — documented as future work in unknowns.
Evidence: `tests/test_ipv6_guard.py` (decision matrix, evaluator,
rulesets, enforcement round-trip, engine wiring).
