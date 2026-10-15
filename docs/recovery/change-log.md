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
