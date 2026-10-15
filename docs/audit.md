# NetFend — Codebase Audit and Root-Cause Analysis

**Audit date:** 2026-10-15
**Audited revision:** `96417c3` ("first commit")
**Auditor:** NetFend Agent
**Status:** Accepted as the basis for the modernization work (see `docs/recovery/task-registry.md`)

---

## 1. Scope and Method

The audit covers the complete tree of the initial commit: `main.sh` (installer),
`net_defender.py` (CLI), and the `netfend` package (`models/threat_profile.py`,
`services/{defense_engine,network_manager,threat_intelligence,device_registry}.py`,
`utils/{config,logging}.py`). Each file was read line-by-line; every claim below
references concrete code. The audit asks one question per symptom the owner
reported: *"why does the system sometimes slow my connection, sometimes protect
me, and sometimes make Wi-Fi hard to use?"*

## 2. Executive Summary

The original NetFend is an **offensive ARP tool mislabeled as a defense**. Its
core "mitigation" is to out-shout attackers by continuously injecting ARP
packets — which makes the protector itself the noisiest device on the network —
and to ARP-poison any device it does not recognize, which by default includes
every new legitimate device on the LAN. There is no firewall, no persistence,
no network-change awareness, no safe rollback, and the uninstall path bounces
the network interface. The performance and connectivity symptoms the owner
observes are **fully explained by NetFend's own behavior**, not only by
attackers.

## 3. Root Causes (Problem Registry IDs referenced as P-x)

### RC-1 / P-1 — Self-inflicted ARP flood ("mitigation" loop)
`defense_engine.py::_active_mitigation_loop` sends `blast_count` ARP packets
every `loop_sleep` seconds **unconditionally**, even at threat level MONITOR
(default: 3 packets every 1 s = ~180 packets/min). At CRITICAL it sends 30
packets every 50 ms = **600 packets/second**. Consequences:

- Wi-Fi is a shared medium: every injected frame consumes airtime and slows
  *the user's own* throughput (owner symptom: "sometimes slows down my own
  connection").
- Continuous gratuitous ARP traffic is itself classified as hostile by sane
  network equipment and by other endpoint protection tools.
- The loop runs even when **no attacker is present** — the cost is paid
  permanently.

**Verdict:** the mitigation is the attack. Any fix that keeps timed blasting
is wrong; defense must be idle-silent (ADR-002).

### RC-2 / P-2 — NetFend attacks unauthorized (i.e., unknown) devices
`defense_engine.py::_mitigate_unauthorized_devices` ARP-poisons every device
registered with `is_authorized == False`. Because
`_periodic_discovery_loop` registers **every discovered device as not
authorized by default**, any new phone/laptop/IoT that joins the LAN is
immediately cut off the gateway (poison mapping to `00:00:00:00:00:00`).
Consequences:

- Legitimate guests are silently disconnected (owner requirement explicitly
  forbids this).
- The poisoning frames increase broadcast/multicast load on the Wi-Fi cell
  (contributes to RC-1 symptom).
- On managed networks this triggers switch port security / AP isolation
  against the *user's own* machine.

**Verdict:** remove entirely. Protection means protecting this device, not
attacking others (ADR-001).

### RC-3 / P-3 — Full-/24 ARP scan every 30 s
`network_manager.py::scan_local_network` sends 254 ARP requests via `srp`
every 30 seconds. That is a permanent background network sweep (~500 packets/
min of scan traffic), which:

- consumes airtime (bandwidth symptom),
- populates every LAN device's ARP cache with the scanner (behaviorally
  indistinguishable from recon),
- produces `srp` timeout CPU wakeups even on idle networks.

**Verdict:** discovery must be passive-first (neighbor table, ARP observation)
with an explicit, rate-limited active scan only on demand.

### RC-4 / P-4 — No firewall, and `arptables -F` destroys global state
The only kernel enforcement is `apply_arptables_rules`, which begins with
`arptables -F` — flushing **all** arp rules system-wide (the user's own rules
included) — then installs 2 INPUT rules. There is:

- no IP-layer firewall at all (no inbound filtering, no SYN/connection rate
  limiting, no scan hardening),
- no cleanup ownership model (a crash leaves rules behind),
- reliance on the legacy `arptables` binary (absent on modern default installs;
  the nftables `arp` family supersedes it).

**Verdict:** move to nftables with engine-owned tables
(`inet netfend_filter`, `arp netfend_arp`) that are created/deleted
atomically and never touch foreign rules (ADR-003).

### RC-5 / P-5 — One-shot network identity, no change detection
`DefenseEngine.__init__` captures `my_ip/my_mac/gw_ip/gw_mac` exactly once.
On DHCP renewal, Wi-Fi roam, VPN up/down or interface change:

- static neighbor entry + arptables rules still reference the **old**
  gateway/IP → enforcement against stale identity is worse than none (it can
  blackhole the user's own gateway path after a legitimate router change),
- the sniff callback compares against stale values → false
  "gateway_spoof" accusations against the *new legitimate* router,
  escalating threat level → more blasting (RC-1 feedback loop).

This is a primary explanation for "sometimes interferes with my connection".

**Verdict:** event-driven network monitoring (netlink/`ip monitor` +
`NetworkManager` state) with re-baselining on every change.

### RC-6 / P-6 — No persistence, unsafe lifecycle
- Engine must be launched manually (`sudo net_protect`); no systemd unit, no
  boot start, no restart-on-crash, no watchdog.
- `stop()` is only invoked on clean `KeyboardInterrupt`; `pkill -f
  net_defender.py` (in `net_reset`) kills without any cleanup → static ARP
  entry and arptables rules **persist after death**, degrading the network
  until manual cleanup.

**Verdict:** systemd unit (`Restart=on-failure`, watchdog), signal handlers,
install/uninstall scripts that always restore state.

### RC-7 / P-7 — Uninstall bounces the interface (Wi-Fi symptom)
`main.sh`'s `net_reset` runs `ip link set $IFACE down; sleep 1; ip link set
$IFACE up`. Consequences: the Wi-Fi association is destroyed; reassociation
must redo auth/DHCP; on networks with sticky AP state or 802.1X this can make
**reconnecting unexpectedly difficult** — matching the owner's recurring
Wi-Fi complaint. It also flushes the neighbor table, briefly breaking
in-flight conversations.

**Verdict:** removal of interface bouncing from all code paths; recovery is
`ip neigh` cleanup + DHCP-managed reconfiguration only.

### RC-8 / P-8 — arptables own-IP rule blocks legitimate ARP
`arptables -A INPUT -s {my_ip} -j DROP` drops *all* ARP frames whose sender
protocol address equals our IP — including DAD (duplicate address detection)
probes from a legitimate device, and any frame during legitimate address
re-use after lease changes. It also silently stops matching after an IP
change (stale rule) while never being re-installed.

**Verdict:** rule must key on *sender MAC ≠ our MAC AND sender IP = our IP*
and be rebuilt on every network change.

### RC-9 / P-9 — Sniff-based detection without efficiency or safety
`sniff(filter="arp", ...)` is acceptable, but the callback does per-packet
registry writes: `register_device()` → **JSON file rewrite on every ARP
packet observed** (registry `save()` writes the whole file). On busy LANs
this is heavy disk churn and lock contention; with the mitigation loop's
blasts (RC-1) the engine re-observes its own injected packets, writing the
registry in a tight loop.

**Verdict:** debounce persistence, and ignore our own transmissions.

### RC-10 / P-10 — Detection gaps for the owner's stated threats
No detection or monitoring exists for: DNS configuration manipulation, rogue
DHCP servers, deauthentication/disassociation patterns, IP-to-MAC flapping
(same IP alternating MACs — the actual NetCut signature beyond gateway
spoof), connection/t throughput health, or bandwidth/latency measurement.
Threat model is limited to two exact-match ARP checks.

**Verdict:** layered guards (ARP, DHCP, DNS, Wi-Fi state, flood/health
metrics) with severity+confidence scoring; explicit documentation of what
client hardware can and cannot see (802.11w recommendation).

### RC-11 / P-11 — Operational hygiene
- `__pycache__/*.pyc` committed to git; no `.gitignore`.
- `data/netfend.log` (empty) committed.
- `install` copies the package to `/usr/local/bin/netfend` (a *bin* dir) and
  leaves no uninstaller; `apt-get install` list includes deprecated
  `net-tools`; no versioning, no health check, no status command.
- No README, no tests, no docs of any kind.
- Logging via `logging.basicConfig` with no rotation → unbounded log growth
  (long-running service requirement violated).

**Verdict:** full repo hygiene pass, install/uninstall with rollback,
rotating logs, tests, README.

### RC-12 / P-12 — Startup fragility
`resolve_mac(gw)` uses `srp` with `timeout=2, retry=3` — up to ~6–8 s
blocking at boot; if the gateway is temporarily silent the engine refuses to
start at all (`RuntimeError`). A defense service must start degraded, not
die.

## 4. What Is Worth Keeping (reuse, not rewrite)

- `models/threat_profile.py` — escalation ladder, timing fingerprint and
  MAC-alias correlation are genuinely good ideas; keep and extend
  (confidence, evidence lists).
- `services/threat_intelligence.py` — profile store + fingerprint map
  design is sound; keep with debounced saves.
- `services/device_registry.py` — data model is fine; keep with persistence
  debounce and observation metadata.
- `net_defender.py` CLI structure — keep as the CLI surface, extend with
  `status`, `doctor`, `events`.

## 5. Symptom → Root-Cause Mapping

| Owner symptom | Root cause(s) |
|---|---|
| "suspicious activity consumes bandwidth" | RC-1, RC-2, RC-3 (NetFend's own traffic) |
| "sometimes blocks, sometimes not" | RC-4, RC-8, RC-12 (rule gaps, stale identity) |
| "slows my own connection" | RC-1, RC-3, RC-9 (airtime + CPU + disk churn) |
| "interferes with my connection" | RC-5, RC-6 (stale enforcement after network change) |
| "Wi-Fi hard to connect" | RC-7 (interface bouncing), RC-2 (poisoned guests/AP countermeasures) |

## 6. Remediation Plan

Derived into `docs/recovery/task-registry.md` (T-1 … T-10) and executed on
`main`. Architectural decisions are recorded in `docs/decisions/`.
