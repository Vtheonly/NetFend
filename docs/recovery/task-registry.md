# Task Registry

One row per task. A task may only be marked `DONE` with evidence (test,
command output, or documented manual verification). Statuses: `TODO`,
`IN PROGRESS`, `DONE`, `BLOCKED`.

| ID | Task | Status | Evidence / notes |
|----|------|--------|------------------|
| T-0 | Consolidate repository to single `main` branch, remove other branches | DONE | Repo audit 2026-10-15: `git ls-remote origin` shows only `refs/heads/main` (single commit `96417c3`). Nothing to merge/delete; branch policy documented in AGENTS.md §6 |
| T-1 | Audit codebase, write root-cause analysis (`docs/audit.md`) | DONE | 12 root causes documented (RC-1…RC-12); symptom→cause mapping included |
| T-2 | Documentation foundation: AGENTS.md, problem/task registries, ADRs, change-log, unknowns | DONE | This file set; ADR-001…ADR-005 |
| T-3 | Repo hygiene: remove committed `__pycache__`, add `.gitignore` | DONE | `git rm -r --cached` for all pycache dirs; `.gitignore` covers pyc/data/logs/tokens |
| T-4 | Rewrite core: config, logging (rotation, optional colorama), event store, pure detection logic | DONE | Commit "T-4 core framework"; verified by `tests/test_config.py`, `test_events.py`, `test_logging.py` |
| T-5 | NetworkManager rework: safe subprocess, defensive parsing, background gateway resolution | DONE | Commit "T-5"; `tests/test_network_manager.py` parses fixture `ip route` outputs incl. point-to-point/metric variants |
| T-6 | Firewall manager: nftables owned tables, dry-run validation, connectivity self-check, rollback+backoff | DONE | Commit "T-6"; `tests/test_firewall.py` covers rule generation, validation gating, rollback on failed check |
| T-7 | ARP guard: gateway spoof, own-IP conflict, IP-MAC flapping, gratuitous floods, confidence scoring | DONE | Commit "T-7"; `tests/test_arp_guard.py` — pure evaluation over synthetic observations incl. false-positive cases (router replacement, DHCP renew) |
| T-8 | DHCP guard: rogue server detection, lease/gateway/DNS change awareness | DONE | Commit "T-8"; `tests/test_dhcp_guard.py` |
| T-9 | DNS guard: resolv.conf watch, resolver sanity checks | DONE | Commit "T-9"; `tests/test_dns_guard.py` |
| T-10 | Wi-Fi diagnostics: failure classification (auth vs DHCP vs DNS vs signal), repeated-disconnect correlation | DONE | Commit "T-10"; `tests/test_wifi_diagnostics.py` |
| T-11 | Metrics: throughput, packet rates, latency/loss, engine CPU/mem, health verdict | DONE | Commit "T-11"; `tests/test_metrics.py` parses /proc/net/dev fixtures |
| T-12 | DefenseEngine orchestration rewrite (event-driven, interruptible, degraded-mode start) | DONE | Commit "T-12"; `tests/test_engine_safety.py` (no periodic send, threads daemon+interruptible) |
| T-13 | systemd service unit + installer + uninstaller with rollback | DONE | Commit "T-13"; `systemd/netfend.service` (watchdog, hardening), `install.sh` (`--dry-run`, `--check`), `uninstall.sh`; syntax checks run (unit validated with `systemd-analyze verify` not available in sandbox — noted in unknowns) |
| T-14 | CLI: status, doctor, events, scan, gateway rebaseline | DONE | Commit "T-14"; manual runs of `net_defender.py --doctor`, `--status` in sandbox (degraded mode) |
| T-15 | Dashboard backend (stdlib HTTP, localhost, token+CSRF, allowlisted API) | DONE | Commit "T-15"; `tests/test_dashboard.py` boots server on ephemeral port, verifies auth matrix (401/403/CSRF), no-secret responses |
| T-16 | Dashboard frontend (HTML/CSS/JS, canvas charts, all required panels incl. Local Network Attack Protection) | DONE | Commit "T-16"; manual screenshot review + `tests/test_static_assets.py` (all endpoints/panels present, no external URLs) |
| T-17 | Tests: full unit suite green on python without scapy | DONE | `python3 -m pytest tests/ -q` → all pass (recorded in change-log) |
| T-18 | README: install, config, platforms, dashboard access, troubleshooting, uninstall, threat model, limits, resource consumption | DONE | Commit "T-18"; `README.md` |
| T-19 | Final verification pass + docs closure + push | DONE | Change-log final entry; all commits pushed to `main` |

## Explicitly out of scope (documented, not silently dropped)

- Router/AP-side enforcement (needs router admin; README documents recommendations).
- Frame-level deauth detection on hardware without monitor mode (P-14/U-2).
- Windows/macOS support (Linux-only; nftables/systemd assumptions documented).
