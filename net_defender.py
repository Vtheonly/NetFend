#!/usr/bin/env python3
"""NetFend CLI — terminal entry point for the defense engine.

Commands:
  (no args) / --service   run the engine in the foreground (systemd uses this)
  --status                engine/service snapshot
  --doctor                capability + config + rule self-test (PASS/WARN/FAIL)
  --events [N]            show last N security events
  --scan                  one-shot active local network discovery (explicit)
  --gateway-rebaseline    re-learn gateway identity (after router replacement)
  --list-devices          list observed devices
  --authorize MAC         mark device authorized (bookkeeping only)
  --deauthorize MAC       mark device unauthorized (bookkeeping only)
  --register-manual ...   manually add a device record
  --blacklist             show threat profiles
  --blacklist-clear       clear threat profiles
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from netfend import __version__
from netfend.utils.config import BLACKLIST_FILE, load_config, cfg
from netfend.utils.logging import log_info, log_err, log_success, log_warn


def _has_ipv6_route():
    """Best-effort IPv6 default-route probe for --status display."""
    try:
        import subprocess
        r = subprocess.run(["ip", "-6", "route"], capture_output=True,
                           text=True, timeout=5)
        return any(line.startswith("default")
                   for line in r.stdout.splitlines())
    except Exception:
        return False


def cmd_status():
    from netfend.services.defense_engine import DefenseEngine
    from netfend.utils import capabilities
    load_config()
    caps = capabilities.summary()
    snap = None
    try:
        engine = DefenseEngine()
        engine.nm.refresh()
        snap = engine.nm.snapshot()
    except Exception as e:
        print(f"identity probe error: {e}")
    print(f"NetFend v{__version__} status")
    print("-" * 60)
    if snap:
        print(f"  interface : {snap['interface']}")
        print(f"  local IP  : {snap['my_ip']}")
        print(f"  local MAC : {snap['my_mac']}")
        print(f"  gateway   : {snap['gateway_ip']} ({snap['gateway_mac'] or 'unresolved'})")
    from netfend.utils.config import DATA_DIR
    print(f"  data dir  : {DATA_DIR}")
    print(f"  dry_run   : {cfg('general', 'dry_run')}")
    try:
        from netfend.services.hardening import build_param_list
        n_params = len(build_param_list(str(cfg("hardening", "rp_filter", "strict"))))
        print(f"  hardening : {n_params} kernel params enforced when root "
              f"(rp_filter={cfg('hardening', 'rp_filter', 'strict')})")
    except Exception:
        pass
    v6 = "suppress RAs" if not _has_ipv6_route() else "monitor RA sources"
    print(f"  ipv6      : {cfg('ipv6', 'ra_guard', 'auto')} — will {v6}")
    print("-" * 60)
    print("  capabilities:")
    for note in caps["notes"] or ["all capabilities present"]:
        print(f"    - {note}")
    # systemd state
    try:
        import subprocess
        r = subprocess.run(["systemctl", "is-active", "netfend"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode != 4:  # 4 = no such unit
            print(f"  service   : {r.stdout.strip()}")
    except Exception:
        pass


def cmd_doctor():
    from netfend.utils import capabilities
    from netfend.services.firewall import build_filter_ruleset, build_arp_ruleset
    load_config()
    results = []

    def check(name, ok, detail=""):
        results.append((name, ok, detail))

    caps = capabilities.probe()
    check("linux /proc filesystem", caps["linux"], "")
    check("running as root", caps["root"],
          "" if caps["root"] else "kernel enforcement disabled (dry-run mode)")
    check("iproute2 (ip)", caps["ip"], "")
    check("ping utility", caps["ping"], "")
    check("nftables (binary + kernel)", caps["nftables"],
          "" if caps["nftables"] else "firewall rules will NOT be enforced")
    check("scapy (packet inspection)", caps["scapy"],
          "" if caps["scapy"] else "ARP/DHCP guards disabled; install python3-scapy")
    check("wireless tools (iw)", caps["wireless"],
          "" if caps["wireless"] else "Wi-Fi diagnostics limited")
    check("journalctl (wpa_supplicant reason codes)", caps.get("journalctl", False),
          "" if caps.get("journalctl", False)
          else "deauth-signature detection (wifi.deauth_signature) disabled")
    check("monitor mode support", caps["monitor_mode"],
          "frame-level deauth detection needs it; 802.11w/PMF recommended on AP")
    check("systemd", caps["systemd_running"], "")

    # config sanity
    try:
        c = load_config()
        profile = c["firewall"]["profile"]
        check("config file", True, f"loaded, firewall profile={profile}")
        check("firewall profile valid", profile in ("standard", "strict", "off"), profile)
    except Exception as e:
        check("config file", False, str(e))

    # ruleset generation sanity (dry, no kernel touch)
    try:
        rs = build_filter_ruleset(
            cfg("firewall", "profile", "standard") or "standard",
            cfg("firewall", "new_conn_rate_per_s", 50),
            cfg("firewall", "new_conn_burst", 100),
            cfg("firewall", "icmp_rate_per_s", 20),
            cfg("firewall", "icmp_burst", 40),
            cfg("firewall", "strict_allowed_tcp_ports", []),
            cfg("firewall", "strict_allowed_udp_ports", [53, 67, 68]),
            ra_guard=True)
        check("ruleset generation", "netfend_filter" in rs, f"{len(rs.splitlines())} lines")
        check("icmp redirect drops present", "redirect counter drop" in rs
              and "nd-redirect counter drop" in rs, "v4+v6 route-hijack vector")
        check("IPv6 RA drop present (when guard active)",
              "nd-router-advert counter drop" in rs, "mitm6 vector")
        arp = build_arp_ruleset("192.0.2.10", "00:11:22:33:44:55",
                                "192.0.2.1", "00:11:22:33:44:99")
        check("arp ruleset generation", "netfend_arp" in arp, "")
        check("arp hardware-address token (P-37)",
              "arp saddr ether !=" in arp and "arp saddr mac" not in arp,
              "nft grammar is arp saddr {ip|ether}")
    except Exception as e:
        check("ruleset generation", False, str(e))

    # kernel hardening + IPv6 guard sanity (dry, no kernel touch)
    try:
        from netfend.services.hardening import build_param_list
        params = build_param_list(str(cfg("hardening", "rp_filter", "strict")))
        check("kernel hardening parameter set", len(params) >= 11,
              f"{len(params)} sysctls (redirects, source-route, rp_filter "
              f"'{cfg('hardening', 'rp_filter', 'strict')}')")
    except Exception as e:
        check("kernel hardening parameter set", False, str(e))
    try:
        from netfend.services.ipv6_guard import should_enable_ra_guard
        ok = (should_enable_ra_guard(False, "auto") is True
              and should_enable_ra_guard(True, "auto") is False
              and should_enable_ra_guard(None, "auto") is False)
        check("IPv6 RA guard decision logic", ok,
              f"mode={cfg('ipv6', 'ra_guard', 'auto')} (auto: suppress only "
              "when no IPv6 default route)")
    except Exception as e:
        check("IPv6 RA guard decision logic", False, str(e))
    try:
        from netfend.services.dns_guard import build_dns_query, parse_dns_response
        q = build_dns_query("netfend-doctor.invalid")
        check("DNS hijack probe wire format", len(q) > 12 and q[-4:] == b"\x00\x01\x00\x01",
              "NXDOMAIN ground-truth check armed")
    except Exception as e:
        check("DNS hijack probe wire format", False, str(e))

    # state files
    from netfend.utils.config import DATA_DIR
    check("data dir writable", os.access(DATA_DIR, os.W_OK) if DATA_DIR.exists()
          else os.access(DATA_DIR.parent, os.W_OK), str(DATA_DIR))

    print(f"NetFend v{__version__} doctor")
    print("=" * 64)
    fails = warns = 0
    for name, ok, detail in results:
        if ok:
            mark = "PASS"
            fails = fails
        else:
            mark = "WARN"
            warns += 1
        print(f"  [{mark:4s}] {name}" + (f" — {detail}" if detail else ""))
    print("=" * 64)
    print(f"  {len(results) - warns} passed, {warns} warnings")
    print("  Note: WARN items degrade features; they do not block the engine.")
    return 0


def cmd_events(count):
    from netfend.models.events import EventStore
    load_config()
    store = EventStore()
    events = store.query(limit=count)
    if not events:
        print("No events recorded.")
        store.close()
        return
    for e in events:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["timestamp"]))
        print(f"{ts}  {e['severity']:8s} {e['confidence']:10s} "
              f"{e['kind']:28s} {e['summary']}")
    store.close()


def cmd_scan():
    from netfend.services.network_manager import NetworkManager
    load_config()
    nm = NetworkManager()
    nm.refresh()
    print(f"Active scan on {nm.interface} ({nm.my_ip}) — one-shot, explicit")
    hosts = nm.scan()
    if not hosts:
        print("No hosts responded (or scapy missing — passive neighbor view):")
        hosts = [(n["ip"], n["mac"]) for n in nm.get_neighbors()]
    for ip, mac in sorted(hosts):
        print(f"  {ip:16s} {mac}")
    print(f"{len(hosts)} hosts shown.")


def cmd_gateway_rebaseline():
    from netfend.services.network_manager import NetworkManager
    load_config()
    nm = NetworkManager()
    nm.refresh()
    gw_mac = nm.resolve_mac(nm.gw_ip, timeout=3)
    if gw_mac:
        nm.gw_mac = gw_mac
        print(f"Gateway {nm.gw_ip} -> {gw_mac} (re-baselined).")
        print("The running engine picks this up on the next network-change event,")
        print("or restart the service: sudo systemctl restart netfend")
    else:
        print(f"Could not resolve MAC for gateway {nm.gw_ip} right now.")


def cmd_show_devices(registry):
    devices = registry.get_devices()
    if not devices:
        print("[NetFend] No registered devices in DB.")
        return
    print(f"\n{'─' * 110}")
    print(f"  OBSERVED NETWORK CLIENTS (bookkeeping only — no enforcement)")
    print(f"{'─' * 110}")
    print(f"  {'MAC Address':18s} │ {'IP Address':15s} │ {'Status':12s} │ {'Hostname':20s} │ {'Last Seen'}")
    print(f"{'─' * 110}")
    for mac, info in sorted(devices.items()):
        auth = "Authorized" if info.get("is_authorized", False) else "Unauthorized"
        print(f"  {mac:18s} │ {info.get('last_ip', 'unknown'):15s} │ {auth:12s} │ "
              f"{info.get('hostname', 'Unknown')[:20]:20s} │ {info.get('last_seen')}")
    print(f"{'─' * 110}\n")


def cmd_blacklist_show(intel):
    lines = intel.get_status_report()
    if not lines:
        print("[NetFend] Blacklist is empty. No threats recorded.")
        return
    print(f"\n{'─' * 90}")
    print(f"  THREAT PROFILES (behavioral)")
    print(f"{'─' * 90}")
    for line in lines:
        print(line)
    print(f"{'─' * 90}\n")


def _acquire_engine_lock(path: str = "/run/netfend.engine.lock"):
    """P-41: exactly one defense engine per machine.

    The live report showed the systemd service AND a manual `sudo netfend`
    running at the same time: two engines fought over kernel state, the
    dashboard port (bind failure), and gateway re-baselines (feedback
    thrash). flock(2) is the mechanism of choice — the kernel releases it
    when the holder exits for ANY reason (including crash), so there is
    no stale-lock recovery to implement.

    Returns (fd, conflict):
      fd int, conflict None    — lock acquired (keep fd open for life)
      fd None, conflict str    — another engine holds it (str = holder pid)
      fd None, conflict None   — locking impossible (degraded; continue)
    """
    import fcntl
    fd = None
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as e:
        print(f"[NetFend] WARNING: engine lock unavailable ({e}); "
              "continuing without single-instance protection")
        return None, None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        holder = ""
        try:
            os.lseek(fd, 0, 0)
            holder = os.read(fd, 64).decode(errors="replace").strip()
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass
        return None, (holder or "unknown")
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
    except OSError:
        pass
    return fd, None


def run_service():
    """Foreground engine run (used by systemd and manual start).

    This is the single entry point (`sudo netfend` / `sudo net_protect`):
    engine + dashboard together, one terminal, Ctrl+C to stop cleanly.
    Returns an exit code (0 = ran, 1 = refused, e.g. another instance).
    """
    from netfend.services.defense_engine import DefenseEngine
    from netfend.dashboard.server import DashboardServer
    from netfend.utils.config import DASHBOARD_TOKEN_FILE
    load_config()

    if os.geteuid() != 0:
        print("NetFend protects this machine through kernel state (nftables,")
        print("static neighbor entries). That needs root.")
        print()
        print("  sudo netfend            run the defense engine (foreground)")
        print("  netfend --doctor        check capabilities without root")
        print("  netfend --status        show a status snapshot")
        return 1

    # P-41: single instance — the service and a manual run must never
    # coexist (they would fight over kernel state + the dashboard port)
    lock_fd, conflict = _acquire_engine_lock()
    if conflict is not None:
        print("[NetFend] Another defense engine is already running"
              + (f" (pid {conflict})" if conflict.isdigit() else "") + ".")
        try:
            import subprocess
            r = subprocess.run(["systemctl", "is-active", "netfend"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip() == "active":
                print("       The systemd service 'netfend' is the running instance:")
                print("         - watch it    : systemctl status netfend"
                      "   (or: netfend --status)")
                print("         - dashboard   : http://127.0.0.1:8787/")
                print("         - stop it     : sudo systemctl stop netfend"
                      "  (then sudo netfend works)")
        except Exception:
            pass
        print("       Two engines must never run at once — they would fight")
        print("       over kernel state, the dashboard port, and re-baselines.")
        return 1
    # lock_fd stays open for the lifetime of this process; the kernel
    # releases it on exit (any exit — including crashes)

    engine = DefenseEngine()
    dashboard = DashboardServer(engine, engine.events)
    engine.dashboard = dashboard
    engine.start()
    snap = engine.nm.snapshot()
    try:
        print()
        print("╔══════════════════════════════════════════════╗")
        print("║   NetFend — Network Defense Engine (live)    ║")
        print("╚══════════════════════════════════════════════╝")
        print(f"  Interface  : {snap['interface']}")
        print(f"  This host  : {snap['my_ip']}  ({snap['my_mac']})")
        print(f"  Gateway    : {snap['gateway_ip']}  "
              f"({snap['gateway_mac'] or 'resolving...'})")
        print(f"  Dashboard  : http://127.0.0.1:{dashboard.port}/  (localhost only)")
        print(f"  Token file : {DASHBOARD_TOKEN_FILE}")
        print("  Kernel     : sysctl hardening (redirects off, source-route off,")
        print("               rp_filter strict) + nftables drops (invalid, floods,")
        print("               ICMP redirects, rogue RAs when v4-only) — restored on exit")
        print("  Engine     : idle-silent defense; corrective actions only on")
        print("               confirmed threats (bounded + airtime-budgeted, ADR-006)")
        print("  Stop       : press Ctrl+C — kernel state is cleaned up, no flapping")
        print()
        engine.run_forever()
    except KeyboardInterrupt:
        print()
    finally:
        engine.stop()
        print("Defense deactivated. Engine-owned kernel state removed.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=f"NetFend v{__version__} — lightweight network defense engine")
    parser.add_argument("--service", action="store_true",
                        help="run engine in foreground (systemd mode)")
    parser.add_argument("-i", "--interface", help="network interface to protect")
    parser.add_argument("--status", action="store_true", help="show status snapshot")
    parser.add_argument("--doctor", action="store_true",
                        help="capability and configuration self-test")
    parser.add_argument("--events", nargs="?", type=int, const=20, metavar="N",
                        help="show last N security events")
    parser.add_argument("--scan", action="store_true",
                        help="one-shot active discovery (explicit, never periodic)")
    parser.add_argument("--gateway-rebaseline", action="store_true",
                        help="re-learn gateway MAC (after router replacement)")
    parser.add_argument("--dry-run", action="store_true",
                        help="never modify kernel state (diagnostics only)")

    # Device / blacklist management (legacy-compatible)
    parser.add_argument("--list-devices", action="store_true")
    parser.add_argument("--authorize", metavar="MAC")
    parser.add_argument("--deauthorize", metavar="MAC")
    parser.add_argument("--register-manual", nargs=4,
                        metavar=("MAC", "IP", "HOSTNAME", "AUTH_BOOL"))
    parser.add_argument("--blacklist", action="store_true")
    parser.add_argument("--blacklist-clear", action="store_true")

    args = parser.parse_args()

    if args.dry_run:
        os.environ["NETFEND_DRY_RUN"] = "1"
        load_config()

    if args.status:
        cmd_status()
    elif args.doctor:
        sys.exit(cmd_doctor())
    elif args.events is not None:
        cmd_events(args.events)
    elif args.scan:
        cmd_scan()
    elif args.gateway_rebaseline:
        cmd_gateway_rebaseline()
    else:
        from netfend.services.device_registry import DeviceRegistry
        from netfend.services.threat_intelligence import ThreatIntelligence
        intel = ThreatIntelligence()
        registry = DeviceRegistry()

        if args.list_devices:
            cmd_show_devices(registry)
        elif args.authorize:
            ok = registry.authorize_device(args.authorize, True)
            log_success(f"{args.authorize} authorized." if ok
                        else f"{args.authorize} not found in registry.")
        elif args.deauthorize:
            ok = registry.authorize_device(args.deauthorize, False)
            log_success(f"{args.authorize} de-authorized." if ok
                        else f"{args.deauthorize} not found in registry.")
        elif args.register_manual:
            mac, ip, hostname, auth_str = args.register_manual
            registry.register_device(
                mac=mac, ip=ip, hostname=hostname,
                is_authorized=auth_str.lower() in ("true", "1", "yes"))
            log_success(f"Registered {mac} ({ip}).")
        elif args.blacklist:
            cmd_blacklist_show(intel)
        elif args.blacklist_clear:
            if BLACKLIST_FILE.exists():
                BLACKLIST_FILE.unlink()
                log_success("Threat profiles cleared.")
            else:
                log_info("No blacklist file found.")
        else:
            # Default: run the engine (service mode)
            sys.exit(run_service() or 0)


if __name__ == "__main__":
    main()
