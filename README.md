# NetFend — Network Defense Engine and Monitoring Dashboard

NetFend is a lightweight, continuously-running network defense and
monitoring system for Linux. It protects **your device** against
local-network attacks (ARP poisoning, gateway impersonation, rogue DHCP,
DNS manipulation, connection flooding), diagnoses connectivity and
Wi-Fi problems with real measurements, and exposes everything through a
localhost-only web dashboard.

NetFend is deliberately **idle-silent**: in steady state it sends zero
packets and adds no measurable latency. All enforcement happens in the
kernel (static neighbor entries + nftables), and userspace only reacts
to events.

---

## What NetFend protects against — and what it cannot

### Threat model (in scope, device-level)

| Threat | Detection | Mitigation on this device |
|---|---|---|
| ARP poisoning / gateway impersonation (NetCut-class) | ARP sniffer + confirmation logic | Static kernel neighbor entry for the gateway; nftables drops ARP frames claiming the gateway IP from a foreign MAC; **sustained corrective self-assertion under attack** (bounded, airtime-budgeted, incl. unicast re-assertion to the gateway — ADR-006/P-28) |
| Own-IP hijack (IP conflict attacks) | ARP sniffer | nftables drops foreign-MAC ARP claiming your IP (DAD-safe); corrective self-assertion |
| IP-to-MAC flapping (poison/anti-poison fights) | Multi-MAC-per-IP window analysis | Alerting + evidence; kernel pin keeps your path stable |
| Gratuitous-ARP floods (cache poisoning) | Per-source rate analysis | Alerting; flooding sources visible in dashboard |
| MAC-rotation attackers (bettercap/NetCut changing MACs) | Behavioral fingerprints + **fuzzy cadence/technique correlation** (P-29) | Alias-group threat-level inheritance; rotation surfaced as `intel.mac_rotation` |
| Rogue DHCP servers | Passive DHCP OFFER/ACK observation with learning window | Alerting (a client cannot block another DHCP server) |
| DHCP lease-option manipulation (router option 3 / DNS option 6 steering — incl. a compromised router) | Baseline comparison **against the kernel-verified gateway** (P-33) | **Override REJECTED**: trusted baseline kept, critical event, threat intel fed, steering target **dropped at nftables line rate** |
| DNS manipulation by the router (fabricated answers, NXDOMAIN hijacking, captive-portal steering) | **NXDOMAIN-hijack signature check**: random `.invalid` label via system resolver + direct public-resolver ground truth (P-34) | Critical event with DoH/DoT + direct public-resolver guidance; standing recommendations when the resolver chain is LAN-only |
| IPv6 takeover (mitm6, rogue RAs / SLAAC) | RA source-conflict detection (P-32) | **Suppressed on v4-only networks**: `accept_ra=0` + nftables rogue-RA drop (ADR-008); monitored when IPv6 is genuinely in use |
| ICMP redirects / source routing (gateway-grade route hijack) | sysctl + nft counters (ADR-007) | `accept_redirects=0` (v4+v6), `accept_source_route=0`, `rp_filter` strict, line-rate redirect drops |
| SYN/UDP connection floods, scans, ICMP floods | nftables meters + counters | Kernel-level per-source rate limiting (drop) |
| Repeated Wi-Fi disconnects (possible deauth attacks) | Disconnect-pattern correlation with ARP/DHCP events | Alerting with confidence level |

All kernel changes are **engine-owned and restored on stop**: sysctl
originals persist to `hardening_state.json` / `ipv6_state.json` before
any write; nftables rules live in `netfend_*` tables; static neighbor
entries are removed — clean Ctrl+C, no interface flapping (ADR-007/008).

### Out of scope (be skeptical of any tool that claims otherwise)

- **Disconnecting an attacker from the Wi-Fi network.** That requires
  router/AP administration. NetFend will never attack other devices
  (this was a root cause of the old version's problems — see
  `docs/audit.md`).
- **Frame-level deauthentication detection** requires monitor mode or
  driver support that most client adapters don't expose. NetFend probes
  this capability and reports it honestly. For management-frame
  protection, enable **802.11w/PMF** on your router/access point.
- **Airtime exhaustion** caused by a Wi-Fi flooder on your channel
  cannot be stopped by any client-side software; NetFend can only
  measure and report it.
- **Router-level visibility** (which device talks to which, client
  isolation, MAC filtering) lives on the router.

### Recommended router-side settings

Enable these on your access point for defense in depth: WPA2/WPA3 with
strong passphrase, 802.11w/PMF (protected management frames), client
isolation if available, DHCP static leases for your own devices, and
router firmware updates.

---

## Requirements

- Linux with `/proc` (systemd-based distributions recommended; tested
  design targets: Debian/Ubuntu)
- Python 3.9+
- `iproute2` (`ip`), `ping` — required
- `nftables` — required for firewall enforcement (kernel + binary)
- Root privileges for enforcement (runs degraded without them)
- Optional: `python3-scapy` (ARP/DHCP packet inspection), `iw` /
  NetworkManager (`nmcli`) for Wi-Fi diagnostics, `psutil` (engine
  CPU/mem stats; falls back to /proc)

Everything optional degrades gracefully with clear warnings in
`netfend --doctor`, the logs, and the dashboard.

## Installation

```bash
git clone https://github.com/Vtheonly/NetFend.git
cd NetFend

# verify the environment first (no changes made)
./install.sh --check

# see exactly what would happen
./install.sh --dry-run

# install (root)
sudo ./install.sh
```

The installer:
- copies the engine to `/opt/netfend`, state to `/var/lib/netfend`,
  config to `/etc/netfend/config.json` (preserved on upgrade)
- installs and enables `netfend.service` (systemd) with restart-on-failure
  and a 30 s watchdog
- **verifies the service actually starts; rolls the whole install back
  if it doesn't**
- installs the `netfend` command plus legacy-name launchers
  (`net_protect`, `net_reset`, `net_watch`, `net_blacklist`) that all
  point at the MODERN engine — and moves any legacy
  `/usr/local/bin/net_defender.py` aside as `*.legacy-disabled`
- generates the dashboard token at `/var/lib/netfend/dashboard.token`
  (mode 0600)

## Single entry point (how to launch it)

One command runs everything — engine + dashboard, in the foreground,
Ctrl+C stops cleanly and removes all engine-owned kernel state:

```bash
sudo netfend
```

The old muscle-memory names keep working and map to the same engine:

| Command | What it does now |
|---|---|
| `net_protect` | same as `sudo netfend` (single entry, foreground) |
| `net_reset` | safe stop — systemctl stop / SIGTERM, **no interface bouncing** |
| `net_watch` | status snapshot + dashboard URL |
| `net_blacklist` | threat profiles (with age decay markers) |

The legacy engine that once lived under `old/` is completely removed;
`docs/architecture/legacy-absorption-map.md` is the permanent record of
where every one of its useful concepts now lives and which flaws were
eliminated instead of ported.

### Manual run (no systemd)

```bash
sudo python3 net_defender.py            # foreground (same as sudo netfend)
sudo python3 net_defender.py --dry-run  # diagnostics only, no kernel changes
```

## CLI

```bash
sudo netfend --status              # identity + capability snapshot
sudo netfend --doctor              # PASS/WARN/FAIL self-test
sudo netfend --events 50           # last 50 security events
sudo netfend --scan                # one-shot active discovery (explicit)
sudo netfend --gateway-rebaseline  # after replacing your router
sudo netfend --list-devices        # observed devices (bookkeeping)
sudo netfend --authorize AA:BB:..  # mark device authorized (label only)
sudo netfend --blacklist           # behavioral threat profiles
sudo netfend --blacklist-clear
```

## Dashboard

- URL: `http://127.0.0.1:8787/` — **localhost only** by default
- Remote access: use an SSH tunnel (`ssh -L 8787:127.0.0.1:8787 host`)
- Read-only telemetry (GET) works from localhost without a token
  (disable via `dashboard.allow_local_readonly: false`)
- Any state-changing action (reload config, re-baseline gateway, change
  firewall profile, rescan) requires:
  1. the token from `/var/lib/netfend/dashboard.token` in the
     `X-NetFend-Token` header, and
  2. a per-session CSRF token obtained via `POST /api/action/session`

Panels: **Network Overview** (identity, live throughput chart, health
verdict), **Security Monitoring** (firewall status/counters, threat
profiles, filterable event log), **Local Network Attack Protection**
(ARP/gateway/DHCP/DNS integrity, active vs unavailable protections,
severity + confidence badges), **Topology** (passively observed hosts
only), **Performance & Diagnostics** (engine CPU/mem, latency/loss, DNS
probe, Wi-Fi info, "why is my internet slow" explanation).

No secrets (Wi-Fi passwords, tokens) are ever displayed or returned by
the API.

## Configuration

`/etc/netfend/config.json` (see `config.example.json`). Highlights:

```jsonc
{
  "general":  { "interface": null, "dry_run": false },
  "firewall": { "profile": "standard" },        // standard | strict | off
  "arp":      { "gateway_confirmations": 2 },
  "dashboard":{ "bind": "127.0.0.1", "port": 8787 }
}
```

- `firewall.profile=standard` (default): policy-accept input chain that
  drops invalid packets and rate-limits floods/scans per source. Your
  legitimate traffic is never throttled.
- `firewall.profile=strict`: default-drop inbound; only established,
  ICMP, DHCP and `strict_allowed_*_ports` pass.
- Unknown config keys produce warnings, never crashes.
- Apply changes: `sudo systemctl restart netfend` or the dashboard's
  reload-config action.

## Service management

```bash
systemctl status netfend
systemctl restart netfend
journalctl -u netfend -f           # structured logs
```

The engine: starts at boot (`multi-user.target`), restarts on failure,
re-baselines identity and re-applies protections on every network
change (DHCP renew, Wi-Fi roam, VPN up/down — via netlink `ip monitor`),
and removes **only its own** kernel state on stop or crash
(`ExecStopPost` cleanup + `systemd` hardening: capability-bounded to
`CAP_NET_RAW`/`CAP_NET_ADMIN`, `ProtectSystem=strict`, 256 MB / 50% CPU
limits).

## Safety guarantees

- Never sends packets in steady state; never attacks other devices.
- nftables rules live in engine-owned tables (`netfend_filter`,
  `netfend_arp`) — user/firewall-frontend rules are never touched.
- Every ruleset is dry-run validated (`nft -c`) and followed by a
  connectivity self-check (gateway ping + DNS); failures roll back
  automatically and back off for 5 minutes.
- Uninstall removes only engine-owned state; permanent neighbor entries
  are converted back to dynamic ones.

## Testing

### Unit tests (no root/network/scapy needed)

```bash
python3 -m pytest tests/ -q
# 95 passed
```

Coverage: config layering, event store (ring/rotation), validators,
parsers (ip route/addr/neigh, /proc/net/dev, iw, nmcli), firewall
ruleset generation + counter parsing, ARP evaluator (spoof/conflict/
flapping/flood + false-positive controls), DHCP evaluator (learning
window, rogue, option changes), DNS evaluator, Wi-Fi classifier, metrics
+ health verdicts, threat profiles/fingerprints, device registry,
engine safety invariants (no packet sends, no global flush, daemon
threads, fast stop), dashboard auth matrix (401/403/CSRF/traversal/
unknown actions), frontend asset checks.

### On-target integration checks (run on the real machine)

```bash
sudo netfend --doctor                    # capabilities + config + rules
sudo nft list table inet netfend_filter  # rules really loaded
sudo nft list table arp netfend_arp
systemctl status netfend                 # service healthy
curl -s http://127.0.0.1:8787/api/overview | python3 -m json.tool
# network change recovery: switch Wi-Fi / replug ethernet, then:
journalctl -u netfend --since "-2 min" | grep -i "network.change"
```

### Simulated attack testing (lab use)

With scapy installed on a second machine you can verify detection:

```bash
# gateway spoof simulation (from attacker box; replaces GW_IP/GW_MAC/IFACE)
sudo scapy -c "sendp(Ether()/ARP(op=2, psrc='GW_IP', hwsrc='attacker_mac', pdst='victim_ip'), iface='IFACE', count=10, inter=0.5)"
# watch the dashboard Security panel / netfend --events on the protected device
```

Expected: `arp.gateway_spoof` (critical/confirmed) once the real
gateway is still active; a `firewall` counter increase on the arp table;
no connectivity loss on the protected device (static pin).

## Resource consumption (measured design targets)

- Idle CPU: < 1% (event-driven; no polling loops beyond cheap 2 s
  /proc reads and a 10 s single ping)
- Memory: < 60 MB typical (systemd-capped at 256 MB)
- Disk: rotating logs/events capped at ~2 MB each (x2 with rotation)
- Network: zero steady-state transmitted packets

## Troubleshooting

| Symptom | Check | Fix |
|---|---|---|
| "Firewall enforcement unavailable" | `netfend --doctor` | install nftables; run as root |
| "ARP inspection unavailable" | doctor | `sudo apt-get install python3-scapy` |
| Gateway shows "unresolved" | `--status` | wait for background resolution; `--gateway-rebaseline` after router replacement |
| Internet feels slow | dashboard Performance panel | the health verdict states the measured cause (loss/latency/DNS/signal) |
| Suspicious ARP alerts after router change | events panel | confirm `arp.gateway_change`, then `--gateway-rebaseline` |
| Dashboard unreachable | `systemctl status netfend` | service must run; check port 8787 not in use |

## Uninstallation

```bash
sudo ./uninstall.sh              # complete removal
sudo ./uninstall.sh --keep-data  # keep events/registry/token
```

## Documentation

- `docs/audit.md` — root-cause analysis of the legacy implementation
- `docs/architecture/architecture.md` — component and data-flow design
- `docs/decisions/ADR-*.md` — architectural decisions and rationale
- `docs/recovery/problem-registry.md` — known problems and status
- `docs/recovery/task-registry.md` — task status and evidence
- `AGENTS.md` — rules for anyone (human or AI) modifying this codebase

## Branch policy

`main` only. All work is committed directly to `main` with detailed
messages (see `docs/recovery/change-log.md`).
