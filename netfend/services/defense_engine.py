"""DefenseEngine — orchestrator of the NetFend defense (event-driven rewrite).

What changed vs. the legacy engine (audit RC-1/2/5/6, ADR-001/002/005):
- NO periodic packet transmission of any kind (idle-silent defense)
- NO attacking of other devices (unauthorized-device poisoning removed)
- network-change aware: `ip monitor` subprocess (link/addr/route/neigh)
  triggers re-baselining + rule re-application
- degraded-mode startup: missing capabilities produce WARNING events,
  never a crash (audit RC-12)
- all threads daemon + Event-interruptible: clean systemd stop < 2 s
- optional sd_notify watchdog when running under systemd
"""
import signal
import subprocess
import threading
import time
from typing import Any, Dict, Optional

from netfend.models.events import EventStore
from netfend.services.active_defense import ActiveDefense
from netfend.services.arp_guard import ArpGuard
from netfend.services.device_registry import DeviceRegistry
from netfend.services.dhcp_guard import DhcpGuard
from netfend.services.dns_guard import DnsGuard
from netfend.services.firewall import FirewallManager
from netfend.services.hardening import KernelHardener
from netfend.services.ipv6_guard import Ipv6Guard
from netfend.services.metrics import MetricsCollector
from netfend.services.network_manager import NetworkManager
from netfend.services.threat_intelligence import ThreatIntelligence
from netfend.services.wifi_diagnostics import WifiDiagnostics
from netfend.utils import capabilities
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn, log_err, log_success


class DefenseEngine:
    """Core orchestrator. Owns all guards; owns no kernel state directly."""

    def __init__(self, interface: Optional[str] = None,
                 events: EventStore = None, dashboard=None):
        self.nm = NetworkManager(interface=interface)
        self.events = events or EventStore()
        self.intel = ThreatIntelligence(events=self.events)
        self.registry = DeviceRegistry()
        self.firewall = FirewallManager(self.nm, self.events)
        self.hardener = KernelHardener(self.events)
        self.ipv6_guard = Ipv6Guard(self.nm, self.events, self.intel)
        self.active_defense = ActiveDefense(self.nm, self.events, self.intel)
        self.arp_guard = ArpGuard(self.nm, self.events, self.registry, self.intel,
                                  on_gateway_rebaseline=self._on_gateway_rebaseline,
                                  on_threat=self.active_defense.handle_threat)
        self.dhcp_guard = DhcpGuard(self.nm, self.events, self.intel,
                                    on_override=self._on_dhcp_override)
        self.dns_guard = DnsGuard(self.nm, self.events)
        self.wifi = WifiDiagnostics(self.nm, self.events)
        self.metrics = MetricsCollector(self.nm, self.events)
        self.dashboard = dashboard

        self.running = False
        self._stop = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_proc: Optional[subprocess.Popen] = None
        self.started_at: Optional[float] = None
        self._rebaseline_lock = threading.Lock()
        self._last_rebaseline = 0.0

    # ------------------------------------------------------------------ start
    def start(self) -> bool:
        if self.running:
            return True
        caps = capabilities.probe()
        self.events.emit_simple(
            "engine.start", "info", "confirmed",
            f"NetFend engine starting (dry_run={cfg('general', 'dry_run')})",
            source="engine", capabilities=caps)
        for note in capabilities.summary()["notes"]:
            self.events.emit_simple("engine.capability", "warning",
                                    "unverified", note, source="engine")

        self.running = True
        self.started_at = time.time()
        self._stop.clear()

        snap = self.nm.refresh()
        if not snap:
            log_warn("Network identity incomplete at start — starting degraded; "
                     "waiting for network-change events")

        # Kernel-resident protection first (idle-silent: ADR-002)
        self._apply_protections()
        if not self.nm.gw_mac:
            self.nm.resolve_mac_background()

        # Guards
        self.arp_guard.start()
        self.dhcp_guard.start()
        self.dns_guard.start()
        self.wifi.start()
        self.metrics.start()
        self.ipv6_guard.start()   # RA conflict detection (mitm6)

        # Network change monitoring
        if cfg("network_monitor", "enabled", True):
            self._start_netlink_monitor()

        # Dashboard (started by engine when embedded)
        if self.dashboard is not None:
            self.dashboard.start()

        self._install_signal_handlers()
        try:
            from netfend.utils.sd_notify import notify_ready
            notify_ready()
        except Exception:
            pass
        log_info("Defense engine active (idle-silent mode; zero steady-state packets)")
        return True

    # ------------------------------------------------------- kernel protection
    def _apply_protections(self) -> None:
        """Static gateway pin + sysctl hardening + firewall (all validated,
        rollback-safe, engine-owned)."""
        snap = self.nm.snapshot()
        gw_ip, gw_mac = snap["gateway_ip"], snap["gateway_mac"]

        # 1) Static neighbor entry protects THIS host's gateway path.
        if gw_ip and gw_mac and not cfg("general", "dry_run"):
            if capabilities.have("root") and capabilities.have("ip"):
                if self.nm.set_static_neighbor(gw_ip, gw_mac):
                    log_info(f"Gateway pinned in kernel neighbor table: {gw_ip} -> {gw_mac}")
                else:
                    log_warn("Could not pin gateway neighbor entry (check privileges)")

        # 2) sysctl hardening (redirects, source-route, rp_filter) — T-31
        self.hardener.apply()

        # 3) IPv6 RA guard decision (before the firewall build: the filter
        #    ruleset takes the RA drop only when suppression is active)
        ra_guard = self.ipv6_guard.evaluate_and_enforce()

        # 4) nftables enforcement (validates + self-checks + rolls back)
        self.firewall.apply(ra_guard=ra_guard)

    # -------------------------------------------------- dhcp override response
    def _on_dhcp_override(self, ev: Dict[str, Any]) -> None:
        """P-33: a confirmed DHCP router-override names a steering target.
        Drop it at line rate (config-gated) so traffic can never flow
        through the attacker's proxy; the kernel default route stays on
        the verified gateway. Runs in a daemon thread (called from the
        DHCP sniffer callback)."""
        def _worker():
            try:
                target = ev.get("evidence", {}).get("pushed_router")
                if not target:
                    return
                if not cfg("dhcp", "drop_override_targets", True):
                    return
                ok = self.firewall.add_override_drop(target)
                self.events.emit_simple(
                    "dhcp.override_dropped", "critical", "confirmed",
                    f"DHCP override target {target} "
                    + ("is now DROPPED at nftables line rate (traffic cannot "
                       "flow through the steering proxy; revert by removing "
                       "the engine tables or setting dhcp.drop_override_targets=false)"
                       if ok else
                       "could not be dropped (firewall table inactive) — "
                       "verify the default route stays on the real gateway"),
                    source="engine", target=target, dropped=ok)
            except Exception as e:
                log_warn(f"DHCP override response failed: {e}")
        threading.Thread(target=_worker, name="nf-dhcp-override",
                         daemon=True).start()

    def _on_gateway_rebaseline(self, gw_ip: str, new_mac: str) -> None:
        """P-19 feedback loop: the ARP guard accepted a legitimate gateway
        MAC change (persistent new MAC, old one silent, no oscillation).
        Re-apply kernel protections with the new trust anchor so the
        static pin and the arp firewall table stop defending a ghost."""
        try:
            log_info(f"Gateway re-baseline: {gw_ip} -> {new_mac}; "
                     "re-applying protections")
            self.events.emit_simple(
                "arp.rebaseline", "notice", "confirmed",
                f"Gateway trust re-baselined to {new_mac}; "
                "static pin and firewall rules re-applied",
                source="engine", gateway_ip=gw_ip, new_mac=new_mac)
            self._apply_protections()
        except Exception as e:
            log_warn(f"Gateway re-baseline protection re-apply failed: {e}")

    # ------------------------------------------------------ network monitoring
    def _start_netlink_monitor(self):
        if not capabilities.have("ip"):
            self.events.emit_simple(
                "monitor.unavailable", "warning", "unverified",
                "Network change monitoring unavailable (iproute2 missing)",
                source="engine")
            return

        def _reader():
            try:
                self._monitor_proc = subprocess.Popen(
                    ["ip", "monitor", "link", "addr", "route", "neigh"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            except OSError as e:
                log_warn(f"Could not start ip monitor: {e}")
                return
            log_info("Network change monitor active (netlink)")
            last_event = 0.0
            for line in self._monitor_proc.stdout:
                if self._stop.is_set():
                    break
                line = line.strip()
                if not line or line.startswith(("Deleted", "prefix")) and "]" not in line:
                    # Heuristic filter: only act on substantial lines
                    pass
                now = time.time()
                # Debounce bursts of netlink events (one re-baseline per burst)
                if line and now - last_event >= 1.0:
                    last_event = now
                    settle = cfg("network_monitor", "settle_delay_s", 3)
                    if self._stop.wait(settle):
                        break
                    self._on_network_change(line)
            try:
                self._monitor_proc.terminate()
            except OSError:
                pass

        self._monitor_thread = threading.Thread(target=_reader, name="nf-monitor",
                                                daemon=True)
        self._monitor_thread.start()

    def _on_network_change(self, detail: str) -> None:
        with self._rebaseline_lock:
            now = time.time()
            if now - self._last_rebaseline < 5:
                return  # rate-limit re-baseline storms
            self._last_rebaseline = now

        old = self.nm.snapshot()
        self.nm.refresh()
        new = self.nm.snapshot()

        identity_changed = (
            old["interface"] != new["interface"]
            or old["my_ip"] != new["my_ip"]
            or old["gateway_ip"] != new["gateway_ip"])

        if identity_changed:
            self.events.emit_simple(
                "network.change", "notice", "confirmed",
                f"Network identity changed: iface {old['interface']}->{new['interface']}, "
                f"ip {old['my_ip']}->{new['my_ip']}, gw {old['gateway_ip']}->{new['gateway_ip']}",
                source="engine", old=old, new=new, detail=detail)
            # remove stale static pin before re-pinning
            if old["gateway_ip"] and old["gateway_ip"] != new["gateway_ip"]:
                if capabilities.have("root") and not cfg("general", "dry_run"):
                    self.nm.remove_static_neighbor(old["gateway_ip"])
            self._apply_protections()
            self.arp_guard.rebaseline()
            if not new["gateway_mac"]:
                self.nm.resolve_mac_background()
        # Silent refresh when only neighbor entries changed (no identity delta)

    # ------------------------------------------------------------------ stop
    def stop(self) -> None:
        if not self.running:
            return
        log_info("Stopping defense engine (clean rollback of engine-owned state)")
        self.running = False
        self._stop.set()

        # Stop guards (each cleans up its own resources)
        for guard in (self.arp_guard, self.dhcp_guard, self.dns_guard,
                      self.wifi, self.metrics, self.ipv6_guard):
            try:
                guard.stop()
            except Exception as e:
                log_warn(f"Guard stop error ({type(guard).__name__}): {e}")
        self.nm.stop()

        if self._monitor_proc:
            try:
                self._monitor_proc.terminate()
            except OSError:
                pass
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)

        # Remove kernel state we own (never foreign rules — ADR-003)
        if not cfg("general", "dry_run"):
            self.firewall.remove()
            self.hardener.restore()
            snap = self.nm.snapshot()
            if snap["gateway_ip"]:
                self.nm.remove_static_neighbor(snap["gateway_ip"])

        if self.dashboard is not None:
            try:
                self.dashboard.stop()
            except Exception:
                pass

        self.intel.stop()
        self.events.emit_simple(
            "engine.stop", "info", "confirmed",
            "Defense engine stopped; engine-owned kernel state removed",
            source="engine")
        self.events.close()
        log_success("Defense engine stopped cleanly")

    # -------------------------------------------------------------- signals
    def _install_signal_handlers(self) -> None:
        def _handler(signum, frame):
            log_info(f"Signal {signum} received — shutting down")
            self.stop()
        try:
            signal.signal(signal.SIGTERM, _handler)
            signal.signal(signal.SIGINT, _handler)
        except (ValueError, OSError):
            pass  # not main thread (e.g. tests) — ignore

    # ----------------------------------------------------------- run/forever
    def run_forever(self) -> None:
        """Block until stopped (used by the CLI entry point)."""
        try:
            while self.running:
                self._stop.wait(1.0)
                self._watchdog()
        finally:
            self.stop()

    def _watchdog(self) -> None:
        """sd_notify watchdog heartbeat when running under systemd."""
        try:
            from netfend.utils.sd_notify import notify
            notify("WATCHDOG=1")
        except Exception:
            pass

    # ------------------------------------------------------------- reporting
    def status(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "started_at": self.started_at,
            "uptime_s": round(time.time() - self.started_at, 1) if self.started_at else None,
            "identity": self.nm.snapshot(),
            "capabilities": capabilities.summary(),
            "firewall": self.firewall.status(),
            "hardening": self.hardener.status(),
            "ipv6": self.ipv6_guard.status(),
            "arp": {"active": self.arp_guard.evaluator is not None,
                    "available": self.arp_guard.available()},
            "active_defense": self.active_defense.status(),
            "dhcp": self.dhcp_guard.status(),
            "dns": self.dns_guard.status(),
            "wifi": self.wifi.status(),
            "threats": self.intel.summary(),
            "devices": len(self.registry.get_devices()),
            "dry_run": bool(cfg("general", "dry_run")),
        }
