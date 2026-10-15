# Legacy Absorption Map — `old/` → `netfend/` (complete)

**Status:** Complete 2026-10-16 (T-36). The `old/` directory is DELETED;
this document is the permanent record that every useful defensive
concept, threshold rule, and mitigation strategy from the legacy engine
(`old/net_defender.py`, "NetFend Pro", 694 lines) is natively
implemented in the modular `netfend/` package — and which legacy flaws
were deliberately eliminated instead of ported.

## A. Absorbed concepts (kept, modernized)

| # | Legacy concept (old/net_defender.py) | Modern implementation | Improvement over legacy |
|---|---|---|---|
| 1 | Graduated threat ladder MONITOR→SUSPECT→HOSTILE→CRITICAL with window-based escalation (`ESCALATION_RULES`) | `netfend/models/threat_profile.py` — identical rule structure | + age-decayed effective level (P-25): a months-old profile cannot dominate; stored history never rewritten |
| 2 | Behavioral fingerprint: burst-interval mean/stddev quantization → sha256; survives MAC changes | `ThreatProfile.get_behavior_fingerprint()` — kept verbatim in spirit | + fuzzy correlation (P-29): timing stats compared with tolerance + technique Jaccard/same-target, so quantization drift no longer breaks MAC-rotation tracking; bidirectional persisted `alias_map`; `intel.mac_rotation` events |
| 3 | `fingerprint_map` alias discovery + threat-level inheritance across matching MACs | `ThreatIntelligence.record_attack()`/`correlate()` | + inheritance works across the whole alias group; notes recorded on both sides; debounced saves (RC-9) |
| 4 | Persistent dynamic blacklist (`/var/lib/netfend/blacklist.json`) | `config.BLACKLIST_FILE` + `ThreatIntelligence.save()` | + debounced writes (legacy wrote the JSON on every packet); crash-tolerant load |
| 5 | Bounded burst size per response (`COUNTERMEASURE_PROFILE.blast_count`) | `arp.corrective_arp_max` (default 5) + `_HARD_MAX_PACKETS = 10` | config-typo-proof hard ceiling; AST-enforced |
| 6 | "Re-assert ourselves so we cannot be cut off" (the part that made the legacy engine 'work' under attack) | `active_defense.py` (ADR-006): event-triggered self-assertion — broadcast GARP + UNICAST reply to the gateway (the exact cache NetCut poisons), kernel gateway re-pin | zero packets when idle (ADR-002); never claims foreign identities (ADR-001); sustained-attack mode with 5 s inter-burst interval and a sliding 30-packets/minute airtime budget (P-28) |
| 7 | Gateway static pin (`ip neigh replace … nud permanent`) | `nm.set_static_neighbor()` + engine `_apply_protections()` | re-applied on network change; re-baselined on legitimate gateway change (P-19); removed cleanly on stop (no wedge on crash — cleanup.sh ExecStopPost) |
| 8 | ARP filter rules (`arptables -A INPUT …`) | nftables `arp netfend_arp` (ADR-003): foreign-MAC-claims-our-IP + foreign-MAC-claims-gateway-IP drops | line-rate; engine-owned table (no global `arptables -F`); per-table validation with fallback ladder (P-18); rebuilt on identity change |
| 9 | Sniff detections: gateway spoof / own-IP conflict / gratuitous-ARP flood | `arp_guard.ArpEvaluator` cases 1–3 | + IP-MAC flapping, gateway oscillation, confirmation windows, per-MAC cooldowns, DAD-probe false-positive fix (RC-8), own-transmission filtering |
| 10 | 60 s periodic blacklist status report | dashboard Security + Local Network Attack Protection panels; `netfend --blacklist`; EventStore | on-demand instead of periodic printing; visible remotely (localhost) |
| 11 | CLI blacklist management (`--blacklist`, `--blacklist-clear`, `--blacklist-detail MAC`) | `net_defender.py` CLI equivalents | same muscle memory; detail surfaced via `--blacklist` (profile summary incl. aliases + randomized-MAC flag) |
| 12 | SIGINT/SIGTERM → stop → save + restore | engine signal handlers + `stop()` | restores firewall tables, static neighbor, sysctl hardening AND accept_ra (ADR-007/008) — with zero packet sends and zero interface flapping; all threads daemon, stop < 2 s |
| 13 | Root check before engine start | `run_service()` non-root explanation path | degrades to diagnostics mode with clear guidance instead of bare exit |
| 14 | net_protect / net_watch / net_reset / net_blacklist launchers | `scripts/legacy-launchers.sh` (T-27) | net_reset no longer bounces the interface (RC-7); all point at the modern engine |

## B. Legacy flaws deliberately NOT ported (eliminated)

| # | Legacy flaw | Why not ported | Modern stance |
|---|---|---|---|
| 1 | Continuous counter-ARP thread on a timer (up to ~600 pps at CRITICAL) | Self-inflicted Wi-Fi airtime DoS (ADR-002); the "effectiveness" came at the cost of everyone's bandwidth | Event-triggered bursts only; hard per-burst ceiling; per-minute airtime budget; idle-silent |
| 2 | Mitigation claimed gateway identity in `_restore_arp` (`psrc=gw_ip, hwsrc=gw_mac` sent from THIS host) | Claims another host's identity (ADR-001 violation) — poisons the LAN from the "defender" | We assert ONLY our own identity; the gateway side is handled by kernel state |
| 3 | `arptables -F` (global flush) | Destroys user/firewall-frontend rules (RC-4) | Engine-owned nftables tables only; never flushed globally |
| 4 | L3 `send(ARP(...))` — `ValueError: Missing 'dst' attribute` crash on stop; stop path skipped the unlock | Crash class leaves `nud permanent` gateway entry wedged (P-22) | Explicit L2 `Ether/ARP` frames; teardown touches only kernel state — structurally impossible |
| 5 | Every gateway ARP frame counted as an attack (63,833 "attacks" by October); blacklist JSON written per packet; `[FINGERPRINT MATCH]` spam per second | Log/disk self-DoS; untrustworthy counters | EventStore dedup folding (P-21); debounced persistence; confirmation windows before counting |
| 6 | Gateway MAC learned once, never re-baselined | Endless false gateway_change flood after legitimate router replacement (P-19) | Trust re-baselining workflow + oscillation classification + engine feedback loop |
| 7 | `shell=True` with f-string commands; `sys.exit` mid-constructor; hard deps on scapy+colorama | Injection surface; brittle startup; crashes on missing deps (RC-12) | `shell=False` + validators everywhere; degraded-mode startup (ADR-005) |
| 8 | `ip neigh flush` + interface bounce in net_reset | Destroys Wi-Fi association (RC-7, the owner's "hard to connect" symptom) | Never bounce interfaces; recovery = clean kernel-state removal |

## C. Capabilities the legacy engine never had (added by the modernization)

- Kernel sysctl hardening with save/restore contract (ADR-007, P-30)
- IPv6 RA guard + rogue-RA conflict detection, the mitm6 vector (ADR-008, P-32)
- ICMP redirect / source-route / rp_filter enforcement (v4+v6)
- DHCP option 3/6 override rejection with line-rate target drops (P-33)
- DNS NXDOMAIN-hijack signature check + encrypted-DNS guidance (P-34)
- Wi-Fi failure classification, metrics/health verdicts, event-driven
  network-change monitoring, systemd service with watchdog, secure
  localhost dashboard, 228-test suite

The legacy engine's git history remains reachable (`git log --follow --
old/net_defender.py`) for archaeology; nothing in the modern engine
depends on `old/` in any way.
