# NetFend Architecture

## 1. Component Map (post-rewrite)

```
                        ┌────────────────────────────────────────────┐
                        │              DefenseEngine                 │
                        │  (orchestrator, lifecycle, watchdog)       │
                        └───────┬───────────────────────────┬────────┘
                                │ owns / feeds             │
   ┌────────────────────────────┼───────────────────────────┼─────────────────────────┐
   │ Guards (detection)         │                           │ State (kernel)          │
   │                            ▼                           ▼                         │
   │  ArpGuard ──────┐   ┌──────────────┐          ┌──────────────────┐              │
   │  DhcpGuard ─────┤   │  EventStore  │◄─────────│ FirewallManager  │              │
   │  DnsGuard ──────┼──►│ (SecurityEve │  events  │ (nft netfend_*)  │              │
   │  Ipv6Guard ─────┤   │  nts, JSONL) │          │ validate/rollback│              │
   │  WifiDiagnostics┤   └──────┬───────┘          │ + override drops │              │
   │  FloodMonitor ──┘          │                  └──────────────────┘              │
   │                             │          ┌──────────────────┐                    │
   │  MetricsCollector ──────────┤          │ KernelHardener   │                    │
   │  (throughput/latency/health)│          │ (sysctl, ADR-007)│                    │
   │  ThreatIntelligence ───────┤          │ + IPv6 accept_ra │                    │
   │  (profiles, MAC-rotation)  │          │ (ADR-008)        │                    │
   │  ActiveDefense ────────────┘          └──────────────────┘                    │
   │  (bounded corrective, ADR-006)             NetworkManager (identity,           │
   └─────────────────────────────────           neighbors, routes, discovery)     │
                                    ┌────────────────────────────────────┐          │
                                    │ DashboardServer (127.0.0.1)        │◄─────────┘
                                    │  static/ + /api/* + auth+CSRF      │   reads EventStore,
                                    └────────────────────────────────────┘   Metrics, guards
```

## 2. Data Flow

1. **Adapters → pure evaluators → EventStore.** Packet/CLI/procfile adapters
   translate raw data into plain dicts; pure `evaluate_*` functions decide
   severity/confidence; results are `SecurityEvent`s.
2. **EventStore** keeps an in-memory ring (dashboard queries), persists
   rotating JSONL (`events.jsonl`), and mirrors WARN+ to the log file.
3. **FirewallManager** consumes identity (from NetworkManager) to compile
   nftables rulesets; applies only after `nft -c`; verifies with a
   connectivity self-check; rolls back on failure with backoff.
4. **NetworkMonitor** (`ip monitor` subprocess) emits link/route/addr/neigh
   changes → engine re-baselines identity → FirewallManager re-applies →
   guards reset baselines (with learning windows to avoid false positives).
5. **DashboardServer** is a read view over EventStore + live guard state;
   the few state-changing actions are token+CSRF gated and allowlisted.

## 3. Key Invariants

- Steady state sends **zero packets** (ADR-002); the only transmitted
  frames are event-triggered corrective ARPs after *confirmed* threats,
  bounded per burst (hard ceiling 10), sustained-mode interval ≥ 5 s,
  and capped by a sliding **30 packets/minute airtime budget** (ADR-006,
  P-28). Every corrective burst asserts only OUR identity (ADR-001).
- Engine-owned kernel state only, each module restoring exactly what it
  changed on stop: nftables `netfend_*` tables (+ dynamic override drops),
  static neighbor entries, sysctl hardening set (`hardening_state.json`,
  ADR-007), and `accept_ra` (`ipv6_state.json`, ADR-008). Stale state
  files from crashed runs are recovered on next apply.
- DHCP lease options are cross-checked against the kernel-verified
  gateway; steering overrides are rejected (baseline kept) and their
  targets dropped at line rate (P-33).
- DNS answers are verified against direct public-resolver ground truth
  (random `.invalid` labels); fabricated answers raise critical
  hijack events with encrypted-DNS guidance (P-34).
- All subprocess calls: argument lists, validated inputs, timeouts.
- Every guard degrades to a WARNING capability event when its tool/privilege
  is missing; the engine itself never exits due to a missing optional
  feature.

## 4. Runtime Layout

| Path | Purpose |
|------|---------|
| `/opt/netfend/` | code (package, CLI, dashboard static) |
| `/etc/netfend/config.json` | user configuration (optional) |
| `/var/lib/netfend/` | state: devices.json, blacklist.json, events.jsonl, dashboard.token, netfend.log |
| `/etc/systemd/system/netfend.service` | service unit |
| `/usr/local/bin/netfend` | CLI symlink to `/opt/netfend/net_defender.py` |

## 5. Threading Model

Main thread: signal handling + sniff dispatch (when scapy present).
Worker threads (all daemon, Event-interruptible): netlink monitor reader,
metrics sampler, DNS watcher, Wi-Fi poller, dashboard HTTP server,
background gateway resolver. `stop()` sets the global event and joins
all threads with 2 s timeout; systemd `Type=notify` + `WatchdogSec=30`
with `sd_notify` heartbeats (no-op when not under systemd).
