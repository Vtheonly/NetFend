# ADR-001 — No offensive packets (protect, never attack)

**Status:** Accepted 2026-10-15
**Context:** The legacy engine ARP-poisoned "unauthorized" devices (any
unknown device, by default) and out-blasted spoofers with timed ARP floods
(audit RC-1, RC-2). This slowed the owner's own Wi-Fi, disconnected
legitimate guests, and is behaviorally an attack tool.

**Decision:** NetFend never emits packets whose purpose is to degrade
another host. All enforcement happens on this device: kernel neighbor
state, nftables filtering, endpoint isolation of *inbound* malicious
flows. Other devices are observed and reported only. Unauthorized-device
"kick" functionality is removed and will not be reintroduced.

**Consequences:** We cannot disconnect an attacker from the Wi-Fi network —
that is router/AP territory (documented in README threat model). We gain:
no self-inflicted airtime consumption, no legal/ethical exposure, no
retaliation from AP-side security that would harm the owner.
