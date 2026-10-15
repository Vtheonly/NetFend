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
tests/test_static_assets.py — required panels/endpoints present in
HTML/JS, zero external http(s) references; manual review.

2026-10-15 — **T-17** (test suite) —
What: 90+ unit tests across 14 files; suite runs green on Python 3.12
without scapy/colorama installed (proves optional-deps requirement).
Command: `python3 -m pytest tests/ -q` → **96 passed**.

2026-10-15 — **T-18** (README) —
What: README.md with: overview, threat model (what is and is NOT
protectable client-side), requirements, install/upgrade/uninstall,
configuration reference, CLI usage, dashboard access + security notes,
testing guide (unit + on-target integration commands), troubleshooting,
resource consumption expectations, limitations. Evidence: rendered
review.

2026-10-15 — **T-19** (closure) —
All tasks T-0…T-19 closed; problems P-1…P-12 FIXED, P-13…P-15
documented limitations; unknowns U-1…U-5 carry next steps. Final push
to `main` on github.com/Vtheonly/NetFend.
