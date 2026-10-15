# Legacy NetFend engine — ARCHIVED, DO NOT RUN

These files are the original pre-modernization engine, kept **only as
reference** for its (few) good ideas that were ported into the modern
engine:

| Legacy idea | Where it lives now |
|---|---|
| Behavioral fingerprinting / MAC-alias correlation | `netfend/services/threat_intelligence.py` |
| Graduated threat levels (MONITOR→CRITICAL) | `netfend/models/threat_profile.py` (+ age decay, P-25) |
| "Works under attack" self-assertion | `netfend/services/active_defense.py` (bounded, ADR-006) |
| Single-command launch (`net_protect`) | `sudo netfend` / installed `net_protect` launcher (P-26) |

## Why the legacy engine must not be executed

Verified from the live session captured in `../report.md` (2026-10-15):

1. **Violates ADR-002** — sends counter-ARP blasts on a timer, up to
   600 packets/s: a self-inflicted DoS on shared Wi-Fi airtime.
2. **Violates ADR-001/003** — `arptables -F` wipes the *global* arp
   filter (destroys user rules); claims other hosts' identities.
3. **Crashes on stop** — `_restore_arp` uses scapy L3 `send(ARP(...))`
   without an Ethernet layer: `ValueError: Missing 'dst' attribute`.
   The crash skips the ARP-table unlock, which can wedge the machine
   with a `nud permanent` gateway entry pointing at a dead MAC.
4. **Runaway counters** — counts every gateway ARP frame as an "attack"
   (63,833 "attacks" accumulated by October), writes the blacklist JSON
   to disk on every single packet, and spams `[FINGERPRINT MATCH]` lines
   once per second.
5. **Static trust** — the gateway MAC learned at startup is never
   re-baselined, so legitimate router changes generate endless false
   `gateway_change` events (the exact flood in `../report.md`).

Run the modern engine instead:

    sudo netfend          # or the legacy-name launcher: net_protect

See `../README.md`, `../docs/audit.md` and `../docs/decisions/` for the
full reasoning.
