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
   │  WifiDiagnostics┤   │  nts, JSONL) │          │ validate/rollback│              │
   │  FloodMonitor ──┘   └──────┬───────┘          └──────────────────┘              │
   │                             │                                                   │
   │  MetricsCollector ──────────┤          NetworkManager (identity, neighbors,     │
   │  (throughput/latency/health)│           routes, passive discovery)              │
   └─────────────────────────────┘                                                   │
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
  frames are optional event-triggered corrective ARPs after a *confirmed*
  poisoning of this host's own cache, bounded and rate-limited (default
  `max 5 per incident`).
- Engine-owned nftables tables only; uninstall/crash cleanup deletes only
  those tables and engine-created static neighbor entries.
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
