"""ActiveDefense — bounded, event-triggered corrective actions (ADR-006).

Why this exists (live report 2026-10-15): the owner reported "somehow the
old engine works better" during a real gateway-spoofing incident. The
legacy engine fought back with counter-ARP blasts (up to 600 packets/s) —
effective at keeping the victim reachable, but itself a DoS on shared
Wi-Fi airtime and a violation of ADR-002 (idle-silent) and ADR-001
(never claim another host's identity). This module implements the SAFE
subset of that capability, triggered ONLY by confirmed threats:

1. Kernel re-pin — when the gateway is under a poisoning attack, restore
   THIS host's neighbor-table view of the gateway to the trusted MAC.
   Pure kernel state: zero packets, instantly heals our traffic path.

2. Self-assertion — up to `arp.corrective_arp_max` (default 5, hard
   ceiling 10) gratuitous ARP replies re-asserting OUR OWN ip->mac to the
   LAN. This is the direct counter to the NetCut "cut the victim off"
   primitive, which poisons the GATEWAY's ARP cache about the victim.
   We NEVER claim the gateway's identity (ADR-001) and NEVER send on a
   timer (ADR-002): every packet is event-triggered, bounded in count,
   and cooldown-gated.

Gates (all must hold before any action):
- config `arp.corrective_arp_enabled` (default true)
- running as root with scapy available and dry_run off
- at least `arp.corrective_arp_cooldown_s` (default 60 s) since the last
  corrective burst

This module is the ONLY place in the engine allowed to transmit packets;
`tests/test_engine_safety.py` enforces that everywhere else stays passive
and that the sends here remain bounded and self-identity-only.
"""
import threading
import time
from typing import Any, Dict, Optional

from netfend.models.events import EventStore
from netfend.utils import capabilities
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn

# hard ceiling independent of config — a typo in config.json must never
# turn the corrective burst into a flood
_HARD_MAX_PACKETS = 10

# only confirmed high-severity findings may trigger a response
TRIGGER_KINDS = {"arp.gateway_spoof", "arp.own_ip_conflict"}


class ActiveDefense:
    def __init__(self, nm, events: EventStore, intel=None):
        self.nm = nm
        self.events = events
        self.intel = intel
        self._lock = threading.Lock()
        self._last_burst: float = 0.0
        self.total_packets_sent = 0
        self.total_bursts = 0
        self.last_action: Optional[Dict[str, Any]] = None

    # -- public ---------------------------------------------------------------
    def enabled(self) -> bool:
        return bool(cfg("arp", "corrective_arp_enabled", True))

    def handle_threat(self, event: Dict[str, Any]) -> None:
        """Entry point wired to ArpGuard.on_threat. Runs in a daemon thread
        so the sniffer callback is never blocked by subprocess/scapy work."""
        if event.get("kind") not in TRIGGER_KINDS:
            return
        threading.Thread(target=self._respond, args=(event,),
                         name="nf-active-defense", daemon=True).start()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "enabled": self.enabled(),
                "last_burst": self._last_burst,
                "total_bursts": self.total_bursts,
                "total_packets_sent": self.total_packets_sent,
                "last_action": self.last_action,
                "capability": "kernel-repin + bounded self-assertion "
                              "(never claims other identities; ADR-006)",
            }

    # -- internals --------------------------------------------------------------
    def _cooldown_ok(self, now: float) -> bool:
        with self._lock:
            if now - self._last_burst >= cfg(
                    "arp", "corrective_arp_cooldown_s", 60):
                self._last_burst = now
                return True
            return False

    def _respond(self, event: Dict[str, Any]) -> None:
        try:
            if not self.enabled():
                return
            if cfg("general", "dry_run"):
                return
            if not (capabilities.have("root") and capabilities.have("scapy")):
                return
            if not self._cooldown_ok(time.time()):
                return

            snap = self.nm.snapshot()
            my_ip, my_mac = snap["my_ip"], snap["my_mac"]
            if not (my_ip and my_mac):
                return

            kind = event.get("kind", "")
            actions: Dict[str, Any] = {}

            # 1) kernel re-pin (no packets) — gateway poison heals our path
            if kind == "arp.gateway_spoof":
                ev = event.get("evidence", {})
                gw_ip = ev.get("gateway_ip") or snap["gateway_ip"]
                trusted = ev.get("pinned_gateway_mac") or snap["gateway_mac"]
                if gw_ip and trusted and capabilities.have("ip"):
                    ok = self.nm.set_static_neighbor(gw_ip, trusted)
                    actions["kernel_repin"] = {
                        "gateway": gw_ip, "trusted_mac": trusted, "ok": ok}

            # 2) bounded self-assertion (our identity only — ADR-001)
            count = max(1, min(int(cfg("arp", "corrective_arp_max", 5)),
                               _HARD_MAX_PACKETS))
            sent = self._send_garps(my_ip, my_mac, count)
            actions["self_assertion"] = {
                "packets": sent, "claimed_identity": f"{my_ip}->{my_mac}"}

            with self._lock:
                self.total_bursts += 1
                self.total_packets_sent += sent
                self.last_action = {"kind": kind, "at": time.time(),
                                    "actions": actions}

            self.events.emit_simple(
                "defense.corrective_action", "notice", "confirmed",
                f"Corrective defense after {kind}: kernel gateway re-pin "
                f"{'done' if actions.get('kernel_repin', {}).get('ok') else 'skipped'}; "
                f"re-asserted our own ARP identity with {sent} packet(s) "
                f"(bounded, event-triggered — never claims other hosts)",
                source="defense", **actions)
            log_info(f"Active defense responded to {kind}: {actions}")
        except Exception as e:  # defense must never crash the engine
            log_warn(f"Active defense error: {e}")

    def _send_garps(self, my_ip: str, my_mac: str, count: int) -> int:
        """Send `count` gratuitous ARP replies asserting OUR OWN identity.

        Uses an explicit L2 frame (Ether + ARP) — the legacy engine's L3
        `send(ARP(...))` crashed with 'Missing dst attribute' because ARP
        has no L3 dst field; that crash class is structurally impossible
        here. Returns the number of packets actually sent.
        """
        try:
            from scapy.all import sendp, Ether, ARP
            pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac) /
                   ARP(op=2, psrc=my_ip, hwsrc=my_mac,
                       pdst=my_ip, hwdst="ff:ff:ff:ff:ff:ff"))
            sendp(pkt, count=count, inter=0.05, verbose=False)
            return count
        except Exception as e:
            log_warn(f"corrective ARP send failed: {e}")
            return 0
