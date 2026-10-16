# Change Log

Format: date — task — what/why/evidence. Newest last.

---

2026-10-15 — **T-0** (branch consolidation) —
What: Cloned repository and audited refs. Why: owner asked to merge all
branches into `main` and delete the others. Evidence: `git ls-remote
origin` lists a single ref `refs/heads/main` @ `96417c3`. The repository
never had other branches; nothing to merge or delete. Branch policy
recorded in AGENTS.md §6.

2026-10-15 — **T-1/T-2/T-3** (audit + docs + hygiene) —
What: Full line-by-line audit of the initial commit; produced
`docs/audit.md` with 12 root causes (RC-1…RC-12) mapping each owner
symptom to concrete code. Created AGENTS.md, ADR-001…005, problem
registry (P-1…P-15), task registry, unknowns, this change-log. Removed
committed `__pycache__` blobs from the index and added `.gitignore`.
Why: owner required audit-driven, documented, incremental work.
Discovery worth persisting: **the engine's own mitigation loop and /24
scanning are the primary self-inflicted bandwidth consumers** (see audit
RC-1/RC-3); any fix that retains timed packet sending reintroduces the
symptom. Evidence: code citations in audit; `git status` clean of pycache
after removal.

2026-10-15 — **T-4** (core framework) —
What: `netfend/utils/config.py` rewritten (JSON config overlay, defaults,
env fallback dir); `netfend/utils/logging.py` rewritten (RotatingFileHandler,
optional colorama with ANSI fallback, JSONL event sink support); NEW
`netfend/models/events.py` (SecurityEvent dataclass + rotating EventStore);
NEW `netfend/utils/validators.py` (MAC/IP/interface regexes — all
subprocess args validated); NEW `netfend/utils/capabilities.py`
(probe-once registry for scapy/colorama/psutil/nft/iw/nmcli/systemd).
Why: ADR-005 (event-driven, optional deps); audit RC-9 (disk churn), RC-11
(log growth). Evidence: tests/test_config.py, test_events.py,
test_logging.py, test_validators.py — 34 tests green.

2026-10-15 — **T-5** (network manager) —
What: `services/network_manager.py` rewritten: `shell=False` everywhere
with arg lists, defensive `ip route` parsing (point-to-point, metric
clauses), neighbor table read via `ip neigh -j`, passive device
observation, gateway resolution moved to background retry (engine no
longer dies when gateway is silent — audit RC-12), static neighbor
entry helpers with stale-entry cleanup. Why: audit RC-5, RC-12, code
safety. Evidence: tests/test_network_manager.py (8 fixture-based tests
incl. malformed output). Discovery persisted: `ip route` default lines
can lack `via` on ptp links — parser handles both orders of `via`/`dev`.

2026-10-15 — **T-6** (firewall manager) —
What: NEW `services/firewall.py`: generates `inet netfend_filter` +
`arp netfend_arp` rulesets; `nft -c` dry-run before apply; connectivity
self-check (gateway ICMP + DNS resolution) after apply; automatic
rollback (delete tables) + cooldown backoff on failure; per-source meter
rate limiting for new inbound connections; ICMP flood limiting; optional
`strict` profile (default-drop inbound). Why: ADR-003; audit RC-4, RC-8.
Evidence: tests/test_firewall.py — rule generation snapshots, invalid
input rejection, rollback triggered on failed self-check (mocked),
no global flush anywhere (grep-verified: no `flush ruleset`).

2026-10-15 — **T-7** (ARP guard) —
What: NEW `services/arp_guard.py`. Pure evaluator + optional scapy sniffer
(BPF `arp`). Detections: gateway spoof (MAC conflict on gw IP), own-IP
conflict, IP-to-MAC flapping (multi-MAC per IP with flap window),
gratuitous-ARP floods (token bucket), unsolicited ARP storm. Confidence
scoring + evidence payloads; legitimate router change handled via
re-baseline workflow (confirmations required before treating new gw MAC
as attack or as new baseline). Why: audit RC-10; owner's NetCut focus.
Evidence: tests/test_arp_guard.py — 15 cases including false-positive
controls (DHCP renew ARP, HA router failover under confirmations).

2026-10-15 — **T-8** (DHCP guard) —
What: NEW `services/dhcp_guard.py`. Passive BPF-filtered capture of
DHCP OFFER/ACK; baseline learning of legitimate server (IP+MAC+options);
rogue server detection after learning window; unexpected
gateway/DNS-option change detection. No packets ever sent. Evidence:
tests/test_dhcp_guard.py (learning window, rogue detection, option
change).

2026-10-15 — **T-9** (DNS guard) —
What: NEW `services/dns_guard.py`. Watches effective resolver
configuration (resolvectl when present, else /etc/resolv.conf mtime+hash
poll at 5 s); detects server-set changes; periodic sanity resolution
(configurable probe domain via system resolver, IPv4 + IPv6) with
failure/slow-resolution events feeding the health panel. Evidence:
tests/test_dns_guard.py (change detection on fixture writes, nxdomain vs
server failure classification).

2026-10-15 — **T-10** (Wi-Fi diagnostics) —
What: NEW `services/wifi_diagnostics.py`. Polls `iw dev link` +
`nmcli --fields ... device/state/connection` when available; state
machine classifies: auth failure, DHCP failure (no IP despite assoc),
DNS failure (assoc+IP but resolution failing), signal problem (RSSI/
link quality thresholds), driver reset (interface flap without
deauth-like pattern), repeated-disconnect correlation (≥N disconnects
in window ⇒ suspicious-pattern event, correlated with ARP/DHCP events
for NetCut-style inference); monitor-mode capability probe (`iw phy`).
Never reconnects by itself. Evidence: tests/test_wifi_diagnostics.py
(classifier matrix, reason-code parsing, correlation window).

2026-10-15 — **T-11** (metrics) —
What: NEW `services/metrics.py`. /proc/net/dev + /sys/class/net
statistics sampling (delta-based rx/tx bytes+packets); gateway latency +
loss via subprocess ping (10 s cadence, single probe); engine CPU/mem
via psutil or /proc/self fallback; health verdict function combining
loss/latency/DNS/connectivity into human explanation ("why is the
internet slow"). Evidence: tests/test_metrics.py (fixture deltas,
verdict matrix).

2026-10-15 — **T-12** (engine rewrite) —
What: `services/defense_engine.py` rewritten as orchestrator: capability
probe → degraded-mode start → guard threads (all daemon, Event-interrupt)
→ netlink monitor (subprocess `ip monitor`, parsed events) → re-baseline
on network change → graceful SIGTERM/SIGINT handling → sd_notify
watchdog when running under systemd. Zero periodic packet transmission.
Removed: mitigation loop, unauthorized-device poisoning, /24 sweeper,
one-shot identity. Evidence: tests/test_engine_safety.py — asserts no
`sendp`/`send`/`srp` on DefenseEngine steady-state paths (source scan),
threads are daemons, stop() joins under 2 s.

2026-10-15 — **T-13** (service + install/uninstall) —
What: `systemd/netfend.service` (After=network-online, Restart=on-failure,
WatchdogSec + sd_notify, hardening directives, ExecStopPost cleanup
helper); `install.sh` (idempotent, --dry-run, --check, rollback on
failed self-test, installs to /opt/netfend, warns-not-fails on missing
optional deps); `uninstall.sh` (stops service, removes engine-owned
nftables tables, static neighbor cleanup, full file removal, --keep-data
option). `main.sh` retained as a thin compatibility wrapper calling
install.sh. Why: audit RC-6, RC-7, RC-11. Evidence: `bash -n` syntax
checks; dry-run executed in sandbox; systemd-analyze unavailable in
sandbox (recorded U-5).

2026-10-15 — **T-14** (CLI) —
What: `net_defender.py` extended: `--status` (service/engine snapshot),
`--doctor` (capability + config + rule self-test with clear PASS/WARN/
FAIL output), `--events [N]`, `--scan` (explicit active discovery),
`--gateway-rebaseline`, legacy device/blacklist subcommands preserved.
Evidence: `--doctor` and `--status` executed in sandbox (degraded mode
correctly reports missing capabilities, exit code 0 with warnings).

2026-10-15 — **T-15** (dashboard backend) —
What: NEW `netfend/dashboard/server.py` + `auth.py`. Stdlib
ThreadingHTTPServer on 127.0.0.1:8787 (configurable). GET /api/* exposes
snapshots (network, security, events, topology, performance, attack
protection); POST allowlist: reload-config, gateway-rebaseline,
firewall-profile, wifi-rescan — each requires token + CSRF; login
rate-limited; token file 0600 auto-generated; no secrets in any
response; static assets served with no directory traversal (path
allowlist). Evidence: tests/test_dashboard.py — auth matrix
(401 unauth POST, 403 bad CSRF, 200 valid), traversal attempts
rejected, static content-type checks.

2026-10-15 — **T-16** (dashboard frontend) —
What: `netfend/dashboard/static/` — index.html + style.css + app.js
(no frameworks, no CDN, offline-capable). Panels: Network Overview
(identity, live throughput canvas chart, historical graphs from
metrics ring buffer), Security Monitoring (event log with
severity/time/type/iface filters, firewall status, rate-limit
counters), Local Network Attack Protection (ARP/DHCP/DNS integrity,
flapping, flood indicators, capability gaps, severity+confidence
badges, confirmed-vs-suspected distinction), Network Topology
(own device, gateway, observed devices — explicitly labeled
"observed", no fabricated links), Performance & Diagnostics (CPU/mem,
latency/loss, gateway/DNS reachability, Wi-Fi info, slow-internet
explanation string from health verdict). Evidence:
tests/test_engine_safety.py::TestStaticAssets — required panels/
endpoints present in HTML/JS, zero external http(s) references; manual
review.

2026-10-15 — **T-17** (test suite) —
What: 95 unit tests across 5 files; suite runs green on Python 3.12
WITHOUT scapy/colorama installed (proves the optional-deps requirement
on the real reference environment). Command: `python3 -m pytest tests/
-q` → **95 passed in ~6s**. Coverage: config layering/unknown-key
warnings/env overrides, EventStore ring+rotation+unwritable-path
degradation, validators, all parsers (ip route/addr/neigh,
/proc/net/dev, iw link, nmcli), firewall ruleset generation for both
profiles + input validation + nft counter parsing, ARP evaluator
(gateway spoof confirmations, router-replacement false-positive
control, own-IP conflict, flapping with DHCP-reassignment control,
garp flood + normal-rate control, malformed input), DHCP evaluator
(learning window, rogue, option changes), DNS evaluator, Wi-Fi failure
classifier matrix, metrics rates + health verdicts, threat profile
escalation/fingerprint-alias/persistence/debounce, device registry
(authorization preserved under passive observation, save=False),
engine safety invariants (AST scan: no packet sends in engine/guards,
no arptables/flush-ruleset anywhere, no interface bouncing, all
threads daemon; runtime: degraded start, stop < 5s), dashboard auth
matrix (static+traversal, 7 endpoints, 401 no-token, 401 bad-token,
403 no-CSRF, 200 token+CSRF, unknown/shell actions 404, bad profile
400, login rate limit, token never echoed), frontend assets (panels,
no external URLs, all endpoints called).
Bugs found BY the tests and fixed immediately (persisted in
AGENTS.md §5): (1) **DeviceRegistry.forget() deadlock** — save() called
while holding the non-reentrant lock; the suite hung on it. (2)
**DhcpEvaluator learning window** counted distinct servers instead of
observations, so the first unknown server after one known server was
silently learned; also option baselines were not seeded during
learning. (3) **config unknown-key warning** compared against the
merged config (where unknown keys exist) instead of DEFAULTS, so it
never fired. (4) **health_verdict.capitalize()** lowercased "DNS" in
the explanation string.

2026-10-15 — **T-18** (README) —
What: README.md with: overview + honest threat model table (in-scope
vs out-of-scope with reasons), recommended router-side settings
(802.11w/PMF etc.), requirements, install (--check/--dry-run/rollback
behavior), CLI reference, dashboard access + auth model + panels,
configuration reference with profile semantics, service management,
safety guarantees, testing (unit + on-target integration + simulated
attack lab commands with expected outcomes), resource consumption,
troubleshooting table, uninstallation, documentation index, branch
policy. Evidence: rendered review.

2026-10-15 — **T-19** (closure) —
What: final verification pass. Full suite `python3 -m pytest tests/ -q`
→ **95 passed**; `python3 -m py_compile` across all modules OK; CLI
`--doctor`/`--status` verified in sandbox (degraded mode with honest
capability warnings); dashboard E2E auth matrix verified live (static,
7 API endpoints, 401/401/403/200 auth chain, traversal 404, unknown
actions 404, invalid args 400); `bash -n` on all shell scripts OK.
Docs closed: task registry T-0…T-19 all DONE with evidence; problems
P-1…P-12, P-16, P-17 FIXED; P-13…P-15 documented limitations; U-1…U-5
carry next steps. All commits pushed to `main` on
github.com/Vtheonly/NetFend (single-branch policy per AGENTS.md §6).

2026-10-16 — **Field-report round** (T-20…T-28, problems P-18…P-27) —
Context: the owner pushed `report.md` + the legacy engine under `old/`
from a live session on the real network (192.168.100.0/24, wlo1,
gateway 192.168.100.1). The report contained dashboard telemetry,
terminal output of the legacy engine, and the request: "make it have
single entry like I did" + "somehow the old engine works better".
Analysis of the report produced 10 new problems (P-18…P-27), all fixed
and regression-tested:

- **T-20 / P-18 (critical):** firewall had left the host with ZERO
  protection — all-or-nothing validation meant the ARP table was never
  applied when the inet filter ruleset was rejected, and events carried
  no nft stderr. Now: per-table independent validation (ARP first),
  fallback ladder full→basic→minimal per table, real error text in
  events, invalid strict-profile rule removed.
- **T-21 / P-19 (critical):** gateway_change event spam (106 rows /
  3 min) — evaluator never re-baselined after a "legitimate change"
  verdict. Now: accepted change re-baselines trust and notifies the
  engine (re-pin + firewall rebuild via daemon-thread callback);
  returning former MACs classify as `arp.gateway_oscillation`
  (aggregated, trust kept); overlapping claims remain spoof conflicts.
- **T-22 / P-21+P-27:** EventStore dedup (identical events within 10 s
  fold into repeat_count, "×N" badge in the UI; JSONL keeps the first
  occurrence per burst) and ring seeding from the JSONL tail — which
  also fixed `netfend --events` always printing nothing after restart.
- **T-23 / P-20+P-22 (ADR-006):** new `active_defense.py` — the safe
  subset of the legacy engine's effectiveness: kernel gateway re-pin +
  bounded self-assertion GARP (≤5 packets, hard ceiling 10,
  event-triggered only, 60 s cooldown, own identity only, explicit L2
  frames). `defense.corrective_action` events; dashboard panel state;
  AST safety tests enforce it stays the only sender.
- **T-24 / P-23:** DHCP false positive fixed — server identity now
  prefers option 54, never keys on 0.0.0.0; gateway-identity servers
  (mesh nodes) learn as infrastructure with a notice; baselines
  persist across restarts.
- **T-25 / P-24:** systemd-resolved stub (127.0.0.53) resolved back to
  effective upstreams; pure stub transitions get one informational
  event instead of a "manipulation" warning per reconnect.
- **T-26 / P-25:** threat aging — 14/30/60-day inactivity decays the
  effective level; stale profiles sink below active ones; returning
  attackers re-escalate instantly through fresh attacks.
- **T-27 / P-26:** single entry — `sudo netfend` prints the legacy-
  style banner and runs engine + dashboard in the foreground;
  `net_protect`/`net_reset`/`net_watch`/`net_blacklist` launchers
  installed pointing at the MODERN engine; the installer moves the
  legacy `/usr/local/bin/net_defender.py` aside as `*.legacy-disabled`;
  `old/README.md` documents why the legacy engine must never run.
- **T-28:** registries/unknowns/AGENTS.md traps updated (see
  problem-registry P-18…P-27, unknowns U-6…U-8, AGENTS.md §5).

Verification: full suite `python3 -m pytest tests/ -q` → **139
passed** (95 before this round); `bash -n` on all shell scripts;
non-root CLI smoke test of the single entry; every task committed and
pushed to `main` individually (a84613d…c33b5b8 + this commit).

Live-network items that still need the owner (documented in U-6…U-8):
confirm whether 1c:73:e2:* is a mesh system or an attacker (check the
router admin page); re-run the engine once so the new
`firewall.validation_failed`/`firewall.fallback` events capture the
exact nft stderr for the primary ruleset hardening; enable 802.11w/PMF
on the router to close the deauth vector at -81 dBm signal strength.

2026-10-16 — **T-29** (sustained-attack corrective defense, P-28) —
What: active_defense.py gained sustained-attack semantics: attack
pressure tracking (fresh trigger inside 12 s window → sustained mode),
5 s inter-burst interval while sustained (60 s cooldown otherwise),
sliding 60 s packet budget (default 30, hard ceiling 60 — config-typo
proof), kernel re-pin moved OUT of the cooldown gate (zero-packet action
now happens on every confirmed spoof), `arp.gateway_oscillation`
(poison fight) added as a trigger kind, and unicast ARP re-assertion to
the gateway added alongside the broadcast GARP (the NetCut primitive
poisons the gateway's cache about the victim — unicast heals exactly
that cache). Why: under continuous re-poisoning the old fixed cooldown
silenced the defense for ~59 of every 60 s, recreating the "legacy
engine works better" gap while staying within ADR-001/002 bounds.
Evidence: tests/test_active_defense.py 7→16 tests, all green; ADR-006
amendment documents the invariants (worst case ~0.5–1 pkt/s under
maximum sustained pressure, zero when the attack stops).

2026-10-16 — **T-30** (fuzzy MAC-rotation correlation, P-29) —
What: ThreatProfile gained timing_stats() (raw mean/stddev/n) and
is_locally_administered() (randomized-MAC bit). ThreatIntelligence
gained correlate(): links profiles whose attack cadence matches within
35% relative mean difference AND whose technique sets overlap (Jaccard
>= 0.5) or who target the same spoofed IP; links are bidirectional,
persisted in alias_map (blacklist.json), inherit the highest threat
level across the group, and surface as intel.mac_rotation events
(engine now wires events into ThreatIntelligence). summary()/CLI
report flag randomized MACs and list aliases. Why: the exact-quantized
fingerprint hash only matched bit-identical cadence; dedicated attack
suites rotate MACs freely while their tool cadence and technique set
stay constant — exactly what the correlator keys on. Evidence:
tests/test_threat_intel.py (15 tests incl. non-correlation guards
against different-cadence/different-tool profiles); suite 162 passing.

2026-10-16 — **T-31** (kernel hardening, P-30) + **P-31 bug fix** —
What: new `netfend/services/hardening.py` (ADR-007): KernelHardener
enforces the zero-trust client sysctl set on engine start —
accept_redirects=0 (v4+v6, all+default), secure_redirects=0,
accept_source_route=0, send_redirects=0, icmp_echo_ignore_broadcasts=1,
rp_filter=strict(1) by config (loose/preserve for asymmetric-routing
setups) — via direct /proc/sys writes (stdlib only), persisting the
pre-change values to hardening_state.json BEFORE writing and restoring
them on engine stop. A stale state file from a crashed run is restored
first so saved originals are always the true pre-hardening values; the
restore path refuses any path outside net/ or containing '..'. Engine
start applies it in _apply_protections() (between gateway pin and
firewall); engine stop restores it next to firewall/neighbor cleanup.
Why: the updated threat model assumes the gateway itself may be
compromised — ICMP redirects and source routing are gateway-grade
attacks no ARP-side defense stops. Bug found while testing: P-31 —
_deep_merge shared nested dicts with DEFAULTS so runtime set_config()
overrides survived config reloads; fixed with a recursive copy.
Evidence: tests/test_hardening.py (16 tests incl. crash recovery and
gates), TestConfigNoDefaultsPollution regressions; suite 180 passing.

2026-10-16 — **T-32** (IPv6 RA guard, P-32) —
What: new `netfend/services/ipv6_guard.py` (ADR-008). Auto mode: when
no IPv6 default route exists (typical v4-only home LAN), suppress RAs
at two layers — sysctl accept_ra=0 (all/default/iface, KernelHardener
save/restore contract with dedicated ipv6_state.json) + nftables
`icmpv6 type nd-router-advert drop` in netfend_filter. When IPv6 IS
in use, monitor instead: >1 distinct RA source in the window emits
critical `ipv6.ra_conflict` (mitm6 signature) and feeds threat intel
with the sender MAC. Unknown routing state (ip -6 unreadable) never
suppresses (fail-open for connectivity); `ipv6.ra_guard=on` forces.
Firewall full+basic variants now ALWAYS drop ICMP redirects (v4
`redirect`, v6 `nd-redirect` — gateway-grade route-hijack vector,
never legitimate for a client), and the RA drop is ordered before the
strict profile's blanket icmpv6 accept. KernelHardener generalized
(custom params/event-prefix/enable-gate/description) so the IPv6 guard
reuses one implementation of the ADR-007 contract. Engine applies the
guard decision before building the firewall ruleset and starts the RA
sniffer with the other guards. Why: attackers pivot to IPv6 when IPv4
is defended (mitm6); the previous engine had zero IPv6 coverage.
Evidence: tests/test_ipv6_guard.py (18 tests); suite 200 passing.

2026-10-16 — **T-33** (DHCP option-override rejection, P-33) —
What: DhcpEvaluator now cross-checks lease options against the
kernel-verified default gateway. Router option (3) pointing anywhere
other than the verified gateway => dhcp.router_override (critical,
confirmed): the trusted baseline is KEPT (the previous code learned
the attacker's value in one observation — the core bug), threat
intel records the server MAC, and the engine (config
dhcp.drop_override_targets, default true) drops the steering target
at nftables line rate (input saddr + output daddr in netfend_filter,
vanishing with the table on stop). DNS option (6) collapsing public
resolvers to LAN-only addresses => dhcp.dns_override (critical,
suspected), baseline kept. Gateway-consistent changes (legit
reconfig/mesh) keep the warning/notice path and ARE learned.
Bug also fixed: evaluator cooldowns seeded with 0.0 meant synthetic
first events inside a 300 s window could never emit (DHCP + DNS
evaluators; production used wall-clock so it was latent) — seeded
with -inf now. Why: zero-trust threat model — the router itself may
be compromised; option pushes are its steering primitive.
Evidence: tests/test_dhcp_override.py (13 tests); suite 213 passing.

2026-10-16 — **T-34** (DNS hijack detection + zero-trust guidance, P-34) —
What: DnsGuard gained an NXDOMAIN-hijack check in the existing probe
cycle (one extra getaddrinfo + at most one small UDP packet): a random
label under .invalid (RFC 2606: reserved non-existent) is resolved via
the SYSTEM resolver; when it unexpectedly answers, a direct query to a
public resolver (hand-built DNS wire format, stdlib socket, bypassing
the local chain entirely) provides ground truth. System answer + direct
NXDOMAIN => dns.hijack_signature (critical, confirmed) carrying
concrete recommendations (systemd-resolved DNSOverTLS with
1.1.1.1#cloudflare-dns.com / 9.9.9.9#dns.quad9.net, or direct public
resolvers, keeping dhcp.dns_override protection on). Direct check
unreachable (UDP/53 blocked) => suspected, not confirmed. Status/
dashboard gained resolvers_lan_only + standing recommendations when the
whole resolver chain is the router's (the exact chain a compromised
router controls). Config: dns.hijack_check (default on),
dns.public_resolvers (default 1.1.1.1, 9.9.9.9). Why: the updated
threat model treats the router itself as potentially hostile — resolver
*set* watching cannot see fabricated answers. Evidence:
tests/test_dns_hijack.py (13 tests, wire format hex-verified); suite
228 passing.

2026-10-16 — **T-35** (operator surfaces, P-35) —
What: doctor +4 checks (ICMP redirect drops present, RA drop present,
kernel hardening parameter set count, IPv6 RA-guard decision matrix,
DNS hijack probe wire format); --status shows the hardening parameter
count and the IPv6 mode with the live route-based decision; the
startup banner documents the kernel defense layer and the
restore-on-exit contract; dashboard attack panel gained an IPv6/mitm6
card (guard state + RA sources seen) and a DNS recommendations block
(LAN-only resolver chain guidance), with the new protections appearing
as chips; config.example.json now carries every key added by T-29..T-34
(hardening, ipv6, dhcp.drop_override_targets, dns.hijack_check +
public_resolvers, corrective sustain keys). The dashboard
firewall-profile action forwards the current RA-guard decision so a
profile switch cannot silently drop the RA rule. Why: capabilities
that the operator cannot see or configure are capabilities they
cannot trust. Evidence: live doctor run in sandbox (output in commit
message), extended static-asset test, suite 228 passing.

2026-10-16 — **T-36** (legacy debt removal, P-36) —
What: `old/` deleted entirely (engine + 5 launchers + symlink, 762
lines). Before deletion every useful defensive concept, threshold
rule, and mitigation strategy was audited against the modern package
and documented in `docs/architecture/legacy-absorption-map.md`:
14 concepts absorbed with concrete improvements (threat ladder +aging,
fingerprints +fuzzy MAC-rotation, alias inheritance +bidirectional
persistence, self-assertion +sustained mode/airtime budget/unicast,
static pin +re-baselining, ARP filtering on nftables, detection cases
+oscillation/flapping, CLI/launcher compat), 8 legacy flaws eliminated
instead of ported (timed blasts, gateway-identity claims, arptables -F,
L3 crash class, per-packet disk writes, static trust, shell=True,
interface bouncing), plus the capabilities the legacy engine never had
(sysctl hardening, IPv6 RA guard, DHCP override rejection, DNS hijack
checks). Hygiene tests now assert old/ stays deleted and no script
references the legacy engine. Why: spec section D — zero residual
legacy files; "archived reference" code that violates the ADRs is a
resurrection hazard. Evidence: TestLegacyDebtRemoved (3 tests); suite
231 passing; git history retains archaeology access.

2026-10-16 — **T-37** (final closure, high-threat modernization) —
What: closed the high-threat engine modernization round. AGENTS.md §5
gained 8 new traps (strict rp_filter vs asymmetric routing, accept_ra
fails open on unknown state + single-owner sysctls, /proc/sys direct
writes with path-refusal, cooldown seeds must be -inf not 0.0, DHCP
baselines are trust anchors, .invalid random-label ground truth,
_deep_merge deep-copy, plus the standing deauth rule). README
threat-model table now documents every new defense with its detection
and mitigation columns; architecture diagram/invariants extended
(KernelHardener, Ipv6Guard, ThreatIntelligence, ActiveDefense, override
drops, airtime budget). Unknowns U-9..U-12 record on-target
verification steps and the remaining future work (DHCPv6 content
inspection, rp_filter/VPN note, v6-vs-v4 LAN decision). Verification:
231/231 tests, doctor 14 passed (degraded env), bash -n clean on all
scripts, every module imports without scapy, old/ absent.
Why: the round's changes must survive the next agent without being
rediscovered. Evidence: this commit + the test suite output above.

2026-10-16 — **T-38** (firewall correctness round 2, P-37..P-40) —
What: the live install report showed `nft -c rejected ruleset` on every
ARP table attempt. Root cause: the ruleset spelled the ARP hardware
address field `arp saddr mac`, but nft's grammar is `arp saddr
{ip|ether}` (the parser error "unexpected string, expecting ether or
ip" points at the exact token position — verified against both error
column variants in the owner's log). Compounding design flaws: the
early return after ARP failure also cancelled the filter table (P-38),
the 300 s cooldown then blocked every re-apply the re-baselines
triggered (P-39), and re-apply would have stacked duplicate rules
because `nft -f` appends (P-40, latent until the syntax was fixed).
Changes: `arp saddr ether` as the primary spelling with a `mac`
fallback candidate in the ladder (full → full-legacy → minimal →
minimal-legacy); table independence in BOTH directions; cooldown keyed
on the failure fingerprint (identity change always re-applies);
apply() deletes engine-owned tables first and re-adds DHCP override
drops after rebuild; remove() unconditional (crash leftovers); doctor
gained the P-37 token check. Why: one invalid token took the whole
kernel layer down while the banner claimed protection — the failure
mode the P-18 round was supposed to have eliminated. Evidence: 5 new
tests in TestRound2FieldFixes; suite 248 passing; owner log columns
4:44-46 / 4:43-45 match the `mac` token position for both host IPs.

2026-10-16 — **T-39+T-40** (engine lifecycle hardening, P-41+P-42) —
What: (1) the systemd service and a manual `sudo netfend` ran
simultaneously — dashboard bind failure, duplicate sniffers, competing
re-baselines; (2) a brief link flap closed all guard sockets (Scapy
"[Errno 100] Network is down") and the guards stayed blind until
restart. Changes: flock-based singleton (`/run/netfend.engine.lock`,
holder pid + systemd guidance on conflict, kernel-released on any
exit); `netfend/utils/sniffer_keeper.py` supervises each guard sniffer
(10 s liveness checks, rebuild bound to the CURRENT interface, bounded
to 6 consecutive restarts then one critical `*.sniffer_gave_up` event);
`sniffer_alive()` in engine status; stop-ordering contract documented
(keeper stops before sniffer). Why: two engines fighting produce the
exact re-baseline thrash seen in the log, and a blind guard during
reconnect is the attacker's favorite window. Evidence:
TestEngineSingletonLock (4) + TestSnifferKeeper (7); suite 248 passing.

2026-10-16 — **T-41** (round-2 field closure) —
What: unknowns U-13/U-14 (on-target verification of the `ether` token
and the keeper under a real flap), AGENTS.md §5 traps for the nft ARP
grammar, nft append semantics, and the single-instance contract.
Why: the sandbox has no nft binary (U-5) — grammar-level bugs can only
be caught by the on-target run, so the verification steps must be
recorded where the next agent sees them. Evidence: this commit;
registries P-37..P-42 / T-38..T-41; suite 248/248; doctor 15 passed.

2026-10-16 — **T-42** (deauth-signature detection, P-43) —
What: the owner's second live incident report showed the pattern the
engine was blind to — router factory-reset (new admin + Wi-Fi
passwords, WPS disabled) did NOT stop the blocking: ~17 min of normal
use, then a slow phase, then locked out — only his device, other
devices unaffected. That is the wireless forged-deauth flood signature
(spoofed AP management frames; needs zero network access, so password
changes are irrelevant). The engine could only count state-transition
disconnects. Changes: SupplicantMonitor reads wpa_supplicant's
CTRL-EVENT-DISCONNECTED lines (reason= + locally_generated=) from the
journal (bounded --since polling, microsecond watermark dedup, 5-failure
give-up); classify_deauth_signature fires `wifi.deauth_signature`
(critical/suspected) on >=4 AP-addressed disconnects (locally_generated=0,
reason in {1,2,7}) within 180 s, with reason counts and the honest fix
list (802.11w/PMF Required + WPA3-SAE + 5 GHz). Client-initiated
deauths never count (false-positive guard); the AP's MAC is never fed
into threat intel (it is the victim's own router); journalctl joined
the capability probe with a doctor check; `deauth_watch` in status;
config keys wifi.supplicant_monitor/supplicant_poll_s/deauth_threshold/
deauth_window_s; version 2.2.0. Why: reason codes are the only
client-side ground truth for WHY a link dropped, they need no monitor
mode, and the owner needs to know that this attack class is fixed at
the ROUTER (PMF/WPA3), not by passwords. Evidence: TestDeauthSignature
(9) + TestSupplicantMonitor (7); suite 264 passing; doctor 16 checks.

2026-10-16 — **T-43** (identity A/B experiment + boot-early evidence, P-44) —

Router-side mitigations are exhausted on the owner's network: the FAYER
router is WPA2-only with no 802.11w/PMF support and the Wi-Fi passphrase
must stay ~8 characters (family constraint, elderly users), so neither
PMF/WPA3 nor a strong PSK is available. The remaining discriminator for
"who is being targeted and at which layer" had to move entirely to the
client. Delivered in three parts:

1. `netfend/services/link_watcher.py` + `netfend-wifi-watch.service`: a
   boot-early READ-ONLY evidence recorder ordered `Before=NetworkManager`
   (DefaultDependencies=no), so the very first association attempt of
   every boot is captured — the window where the owner's blocking
   actually happens. Sources: `iw event -f` (kernel 802.11 management
   events), boot-backfilled journalctl reason codes (same bounded-poller
   pattern as P-43), and state polls (iw link + ip addr/route/neigh +
   one gateway ping), all into one JSONL log where every record carries
   the MAC address in use at observation time — the annotation that
   makes A/B phases interpretable after the fact. Pattern records:
   deauth bursts (reuses classify_deauth_signature) and gateway-MAC
   flapping while associated. The watcher never touches kernel state and
   holds its own flock (/run/netfend.wifi-watch.lock), so it cannot
   fight the engine (P-41 discipline); rotation keeps one predecessor
   file and external writers (phase markers) open per write so rotation
   can never splice a line.

2. `netfend/services/identity_lab.py`: the identity experiment with a
   restore contract. Backup file is the atomic recovery point (created
   before anything changes, deleted only after a VERIFIED restore,
   auto-heals a leftover from a crashed run); every phase (real vs
   randomized locally-administered MAC + dhcp-send-hostname suppression)
   writes markers into the evidence log, reconnects, polls
   assoc/IP/gateway state, and classifies the outcome — including
   `connected_no_gw` for the L3-cut signature (associated + IP but the
   gateway never answers = ARP-level cut, the NetCut case). The verdict
   matrix distinguishes: identity_targeted (static target list keyed on
   the usual MAC/hostname), not_identity_only (whitelist-style
   re-learning or non-identity blocking), no_active_blocking (must
   repeat during an incident), unknown_mac_rejected (router-side
   access control — check before concluding anything). Reports (md+json)
   land in DATA_DIR/abtest/ with the evidence timeline attached.

3. CLI `netfend wifi watch|events|identity|abtest|report` (pre-scanned
   before the flag parser so the legacy CLI is untouched) + doctor check
   for nmcli + wifi-watch line in --status.

Two latent bugs fixed en route: SupplicantMonitor now backfills the
whole current boot (watermark 0 + `-b` bound — the engine previously
started blind to the exact window under attack), and parse_iw_link now
accepts float dBm ("-63.00 dBm", what modern kernels print). Suite 264
-> 334 passing (+70). Version 2.3.0. Remaining owner actions: U-17
(watcher ordering on his distro), U-18 (NM property support), U-19
(the verdict only means something during a blocking episode).
