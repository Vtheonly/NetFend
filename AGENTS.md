# NetFend — Agent Working Rules (AGENTS.md)

> **Read this file completely before making any change to this repository.**
> These rules exist because every one of them addresses a failure that already
> happened in this codebase or in its deployment history. Violating them
> reintroduces known bugs.

## 1. Golden Rules

1. **Never attack other devices on the network.** NetFend must not send ARP
   poison, deauth frames, or any packet whose purpose is to disconnect or
   degrade *another* host. The old `_mitigate_unauthorized_devices()` did
   exactly this and it is forbidden. We protect *this device*; we only
   *observe and report* others. See `docs/decisions/ADR-001-no-offensive-packets.md`.
2. **No periodic packet blasting.** The engine must be idle-silent. Any
   mitigation that sends traffic on a timer (the old "restoration blasts")
   is a self-inflicted DoS on Wi-Fi airtime. Defense is done with kernel
   state (static neighbor entries, nftables), not with packet floods.
   See `docs/decisions/ADR-002-idle-silent-defense.md`.
3. **Own nftables tables only.** All firewall rules live in the `netfend_*`
   nftables tables. Never call `nft flush ruleset` or `arptables -F`
   (the old code flushed the *global* arp table — it could destroy rules
   the user or their firewall frontend created).
4. **Validate then commit, with rollback.** Any firewall or neighbor change
   must be followed by a connectivity self-check (gateway ping + DNS
   resolution). On failure the change must be rolled back automatically
   and the failure recorded. See `netfend/services/firewall.py`.
5. **Every external dependency is optional.** `scapy`, `colorama`, `psutil`,
   `nft`, `iw`, `nmcli`, `systemd` — the engine must boot, log clear
   capability warnings, and keep the parts that work when any of them is
   missing. Missing tools degrade features; they never crash the engine.
6. **Static IP/MAC blocklists are hints, not truth.** Identification of
   hostile behavior must combine multiple indicators (timing fingerprints,
   technique sets, IP-MAC flapping) because attackers change MACs and IPs.
   The `ThreatProfile` fingerprint mechanism exists for this reason.
7. **Never auto-classify unusual as hostile.** Congestion, DHCP renewals,
   legitimate roaming and gateway MAC changes (routers do get replaced,
   and some HA pairs flap legitimately) must be distinguished from attacks
   via evidence and configurable thresholds. Events carry `severity`
   AND `confidence`.
8. **The dashboard is read-only by default.** It binds to 127.0.0.1, needs
   a token for anything state-changing, and never exposes shell execution,
   raw firewall editing, or secrets (no Wi-Fi passwords, no tokens in API
   responses). See `docs/decisions/ADR-004-dashboard-security.md`.

## 2. Required Workflow (per task)

For every task you complete:

1. Implement the fix.
2. Test and verify it (unit tests in `tests/`, plus manual/integration
   evidence recorded in the commit message or docs).
3. Update documentation: what was wrong, why, what changed, what was
   verified, what remains unresolved.
4. Mark the task completed in `docs/recovery/task-registry.md`.
5. Update `docs/recovery/problem-registry.md` for the related problem.
6. Update `docs/recovery/change-log.md`.
7. Create a detailed Git commit (task ID, changes, why, tests, remaining
   work, related problem IDs) and push to `main`.

**Do not mark anything completed or verified without actual evidence.**

## 3. Persist New Discoveries Immediately

If you discover a new problem, undocumented constraint, root cause, or
surprising interaction: document it *immediately* in the right place —
never leave it only in chat or memory:

- `AGENTS.md` — permanent agent rules / safeguards (this file).
- `docs/recovery/problem-registry.md` — newly discovered problems.
- `docs/recovery/unknowns.md` — unresolved questions.
- `docs/architecture/` — architectural discoveries.
- `docs/decisions/` — important architectural decisions (ADRs).
- `docs/recovery/change-log.md` — significant discoveries or changes.

The next agent must not have to rediscover the same problem.

## 4. Code Constraints

- Python 3.9+ (deployment targets: Debian/Ubuntu with python3).
  Do not use match statements or 3.11+ only syntax.
- Third-party imports (`scapy`, `colorama`, `psutil`) must be wrapped in
  `try/except ImportError` with a feature flag recorded in
  `Capabilities`. Detection logic lives in pure functions that take plain
  data (dicts/tuples) so tests run on a machine with no network, no root
  and no scapy. Sniffers/adapters translate raw packets into plain data
  and call the pure functions.
- Subprocess calls: always `shell=False`, always `timeout=`, never build
  commands from unvalidated user input. MAC/IP arguments are validated
  with the regexes in `netfend/utils/validators.py` before being used in
  a command line.
- Long-running loops: every sleep must be interruptible (event.wait), so
  systemd stop is fast and clean. Every thread must be a daemon.
- Log with `netfend.utils.logging` only (rotation configured there).
  Security-relevant findings additionally go through `EventStore.emit()`
  so the dashboard can render them.
- Files written at runtime go to `DATA_DIR` (`/var/lib/netfend` or
  `./data` fallback when not root). Never write to `/etc` at runtime.
- Config is loaded from `/etc/netfend/config.json` when present, else
  built-in defaults. Unknown config keys are warned about, never crash.
- Keep the repo clean: never commit `__pycache__`, `*.pyc`, runtime data,
  logs or tokens. `.gitignore` enforces this — extend it if new artifacts
  appear.

## 5. Known Traps (do not reintroduce)

- `threading.Lock` is NOT reentrant: never call a method that acquires
  the same lock while already holding it. Found as a real deadlock in
  `DeviceRegistry.forget()` (calling `save()` inside the lock) on
  2026-10-15 — the test suite hung because of it. If a method must
  both mutate under lock and persist, do the mutation under the lock,
  then call `save()` AFTER releasing it.
- Python's `str.capitalize()` lowercases every character after the
  first — it destroyed "DNS" in a user-facing verdict string. Use
  explicit casing, not `capitalize()`, for mixed technical strings.

- `arptables` is legacy and often absent; even when present, flushing it
  globally destroys user rules. Use nftables `arp` family in our own table.
- `ip neigh replace ... nud permanent` requires the interface to exist and
  be up; on network change the old static entry is invalid and must be
  removed (the engine handles this on every network-change event).
- `ip -j addr` JSON puts the interface address under the key `"local"`
  (NOT `"addr"` — that key does not exist for `family: inet`). Verified
  against iproute2 on 2026-10-15; the parser accepts both but always
  read `local` first.
- `ip route` default line parsing: `via` may be absent (point-to-point), and
  `dev` may be followed by a metric clause. Parse defensively.
- Bouncing an interface (`ip link set X down/up`) to "fix" connectivity
  destroys Wi-Fi associations and can make reconnection difficult
  (documented root cause of past behavior). Only NetworkManager or the
  user should do this, with explicit consent.
- scapy `sniff(store=0)` with a BPF filter is acceptable *only* with a
  narrow filter (`arp`, `udp port 67`). Unfiltered sniffing burns CPU.
- Gateway MAC learned once at startup goes stale: a legitimate router
  change or DHCP event makes old "protections" poison traffic with wrong
  mappings. Gateway identity is re-baselined on every network change and
  confirmed via multiple observations before enforcement. **Trust must
  also move when the ARP guard accepts a legitimate gateway change** —
  the evaluator re-baselines itself and calls the engine callback
  (re-pin + arp-table rebuild). Forgetting the callback reintroduces the
  P-19 event flood (found live 2026-10-15: 106 identical
  `arp.gateway_change` events in ~3 min).
- Firewall changes must never be all-or-nothing across tables (found
  live 2026-10-15, P-18): a rejected `inet` filter ruleset must not
  block the `arp` table — apply tables independently, each with a
  simpler fallback ruleset, and always surface the actual `nft` stderr
  in the event (an event that says "validation failed" without the
  error text is undiscoverable).
- Every event type that can fire per-packet needs a dedup/cooldown path:
  the EventStore folds identical (kind, summary) events within
  `event_dedup_window_s`, and evaluators add their own per-MAC cooldowns.
  A detection without rate control becomes a self-inflicted log flood
  (P-19/P-21).
- `nft -c` validation results depend on the local nft version: meters
  (per-source dynamic sets) are the least portable construct. New rules
  go into the full variant only; the basic/minimal fallbacks must stay
  meter-free (P-18).
- BOOTP `siaddr` is routinely `0.0.0.0` — never use it as a DHCP server
  identity; prefer DHCP option 54 (P-23). A DHCP server identifying as
  the current gateway IP and offering it as the router option is mesh
  infrastructure, not a rogue (flag as notice, learn into baseline).
- `127.0.0.53` in resolv.conf is the systemd-resolved stub — resolve it
  back to effective upstreams (resolvectl) before comparing resolver
  sets, or every Wi-Fi reconnect looks like DNS manipulation (P-24).
- `EventStore()` starts with an EMPTY ring: anything that must survive
  process restarts (CLI `--events`, dashboard history) relies on
  `_load_tail()` seeding from the JSONL (P-27). New stores that skip
  loading must have a reason.
- Deauth detection requires monitor mode or specific driver support; most
  client adapters cannot see management frames destined to other stations.
  Never claim detection capability the hardware cannot provide — report
  it as unavailable and recommend 802.11w/PMF on the AP instead.

## 6. Repository Conventions

- Branch policy: **`main` only**. All work is committed to `main`.
  (Repository was consolidated to a single `main` branch on 2026-10-15;
  there are no other branches.)
- One logical task per commit, detailed message (see §2).
- Tests: `python3 -m pytest tests/ -q` must pass before every commit.
- Runtime artifacts (data dir) must never be committed.
