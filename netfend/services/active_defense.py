"""ActiveDefense — bounded, event-triggered corrective actions (ADR-006).

Why this exists (live report 2026-10-15): the owner reported "somehow the
old engine works better" during a real gateway-spoofing incident. The
legacy engine fought back with counter-ARP blasts (up to 600 packets/s) —
effective at keeping the victim reachable, but itself a DoS on shared
Wi-Fi airtime and a violation of ADR-002 (idle-silent) and ADR-001
(never claim another host's identity). This module implements the SAFE
subset of that capability, triggered ONLY by confirmed threats:

1. Kernel re-pin — when the gateway is under a poisoning attack (spoof
   conflict OR a poison/anti-poison oscillation fight), restore THIS
   host's neighbor-table view of the gateway to the trusted MAC. Pure
   kernel state: zero packets, instantly heals our traffic path. The
   re-pin is NOT cooldown-gated: it costs nothing and is the single
   most effective counter we own.

2. Self-assertion — up to `arp.corrective_arp_max` (default 5, hard
   ceiling 10) gratuitous ARP replies re-asserting OUR OWN ip->mac to
   the LAN, plus the same number of UNICAST replies to the gateway
   (the NetCut primitive poisons the *gateway's* cache about the
   victim — the unicast heals exactly that cache with minimal airtime).
   We NEVER claim the gateway's identity (ADR-001) and NEVER send on a
   timer (ADR-002): every packet is event-triggered, bounded in count,
   and cooldown-gated.

Sustained-attack mode (P-28): a fixed 60 s cooldown silences us while
an attacker re-poisons every 1-2 s — exactly when the legacy engine
"worked better". Now:
- fresh trigger evidence within `corrective_sustain_window_s` (12 s)
  of the previous trigger marks SUSTAINED attack mode
- in sustained mode bursts may repeat every
  `corrective_sustain_interval_s` (5 s) instead of 60 s
- a sliding 60 s packet budget (`corrective_packets_per_minute`,
  default 30, hard ceiling 60) caps total airtime regardless of attack
  pressure — a config typo can never turn defense into a flood
- when the attack stops, the normal cooldown applies again

Gates (all must hold before any packet):
- config `arp.corrective_arp_enabled` (default true)
- running as root with scapy available and dry_run off
- at least the mode-appropriate interval since the last burst
- per-minute packet budget not exhausted

This module is the ONLY place in the engine allowed to transmit packets;
`tests/test_engine_safety.py` enforces that everywhere else stays passive
and that the sends here remain bounded and self-identity-only.
"""
import threading
import time
from collections import deque
from typing import Any, Dict, Optional

from netfend.models.events import EventStore
from netfend.utils import capabilities
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn

# hard ceilings independent of config — a typo in config.json must never
# turn the corrective burst into a flood
_HARD_MAX_PACKETS = 10            # per burst
_HARD_MAX_PACKETS_PER_MIN = 60    # sliding 60 s airtime budget

# only confirmed high-severity findings may trigger a response.
# gateway_oscillation is included (P-28): a MAC trade-war over the gateway
# IP is an active poison fight — the host must keep asserting itself.
TRIGGER_KINDS = {"arp.gateway_spoof", "arp.own_ip_conflict",
                 "arp.gateway_oscillation"}

# kinds that carry gateway identity in evidence and warrant a kernel re-pin
_REPIN_KINDS = {"arp.gateway_spoof", "arp.gateway_oscillation"}


class ActiveDefense:
    def __init__(self, nm, events: EventStore, intel=None):
        self.nm = nm
        self.events = events
        self.intel = intel
        self._lock = threading.Lock()
        self._last_burst: float = 0.0
        self._last_trigger: float = 0.0
        self._sustained: bool = False
        self._burst_history: "deque" = deque()   # (ts, packets) within 60 s
        self.total_packets_sent = 0
        self.total_bursts = 0
        self.budget_skips = 0
        self.last_action: Optional[Dict[str, Any]] = None

    # -- public ---------------------------------------------------------------
    def enabled(self) -> bool:
        return bool(cfg("arp", "corrective_arp_enabled", True))

    def handle_threat(self, event: Dict[str, Any]) -> None:
        """Entry point wired to ArpGuard.on_threat. Records attack
        pressure, then responds in a daemon thread so the sniffer
        callback is never blocked by subprocess/scapy work."""
        if event.get("kind") not in TRIGGER_KINDS:
            return
        self._note_pressure(time.time())
        threading.Thread(target=self._respond, args=(event,),
                         name="nf-active-defense", daemon=True).start()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            used = sum(p for ts, p in self._burst_history
                       if now - ts <= 60)
            return {
                "enabled": self.enabled(),
                "sustained_attack_mode": self._sustained,
                "last_burst": self._last_burst,
                "last_trigger": self._last_trigger,
                "total_bursts": self.total_bursts,
                "total_packets_sent": self.total_packets_sent,
                "packets_last_minute": used,
                "packets_per_minute_ceiling": min(
                    int(cfg("arp", "corrective_packets_per_minute", 30)),
                    _HARD_MAX_PACKETS_PER_MIN),
                "budget_skips": self.budget_skips,
                "last_action": self.last_action,
                "capability": "kernel-repin + bounded self-assertion "
                              "(broadcast + unicast-to-gateway; never claims "
                              "other identities; ADR-006)",
            }

    # -- internals --------------------------------------------------------------
    def _note_pressure(self, now: float) -> None:
        """Sustained-attack tracking (P-28): a trigger arriving within the
        sustain window of the previous one means the attack is ongoing."""
        with self._lock:
            window = float(cfg("arp", "corrective_sustain_window_s", 12))
            self._sustained = (now - self._last_trigger) <= window
            self._last_trigger = now

    def _min_interval(self) -> float:
        if self._sustained:
            return max(1.0, float(cfg("arp", "corrective_sustain_interval_s", 5)))
        return float(cfg("arp", "corrective_arp_cooldown_s", 60))

    def _cooldown_ok(self, now: float) -> bool:
        with self._lock:
            if now - self._last_burst >= self._min_interval():
                self._last_burst = now
                return True
            return False

    def _budget_ok(self, now: float, packets: int) -> bool:
        """Sliding 60 s airtime budget (P-28). Hard ceiling independent of
        config so a typo cannot authorize a flood."""
        with self._lock:
            while self._burst_history and now - self._burst_history[0][0] > 60:
                self._burst_history.popleft()
            used = sum(p for _, p in self._burst_history)
            ceiling = min(int(cfg("arp", "corrective_packets_per_minute", 30)),
                          _HARD_MAX_PACKETS_PER_MIN)
            if used + packets <= ceiling:
                self._burst_history.append((now, packets))
                return True
            self.budget_skips += 1
            return False

    def _respond(self, event: Dict[str, Any]) -> None:
        try:
            if not self.enabled():
                return
            if cfg("general", "dry_run"):
                return
            if not (capabilities.have("root") and capabilities.have("scapy")):
                return

            snap = self.nm.snapshot()
            my_ip, my_mac = snap["my_ip"], snap["my_mac"]
            if not (my_ip and my_mac):
                return

            kind = event.get("kind", "")
            ev = event.get("evidence", {})
            actions: Dict[str, Any] = {}

            # 1) kernel re-pin (zero packets — never cooldown/budget gated)
            if kind in _REPIN_KINDS:
                gw_ip = ev.get("gateway_ip") or snap["gateway_ip"]
                trusted = (ev.get("pinned_gateway_mac")
                           or ev.get("trusted_mac")
                           or snap["gateway_mac"])
                if gw_ip and trusted and capabilities.have("ip"):
                    ok = self.nm.set_static_neighbor(gw_ip, trusted)
                    actions["kernel_repin"] = {
                        "gateway": gw_ip, "trusted_mac": trusted, "ok": ok}

            # 2) bounded self-assertion (our identity only — ADR-001).
            #    Cooldown AND per-minute budget gate every packet.
            count = max(1, min(int(cfg("arp", "corrective_arp_max", 5)),
                               _HARD_MAX_PACKETS))
            gw_ip = ev.get("gateway_ip") or snap["gateway_ip"]
            gw_mac = (ev.get("pinned_gateway_mac") or ev.get("trusted_mac")
                      or snap["gateway_mac"])
            now = time.time()
            if self._cooldown_ok(now):
                planned = count * (2 if (gw_ip and gw_mac) else 1)
                if self._budget_ok(now, planned):
                    sent_b = self._send_garps(my_ip, my_mac, count)
                    sent_u = 0
                    if gw_ip and gw_mac:
                        # heal the gateway's cache about us (NetCut counter)
                        sent_u = self._send_gateway_unicast(
                            my_ip, my_mac, gw_ip, gw_mac, count)
                    sent = sent_b + sent_u
                    with self._lock:
                        self.total_bursts += 1
                        self.total_packets_sent += sent
                        self.last_action = {"kind": kind, "at": now,
                                            "actions": actions}
                    actions["self_assertion"] = {
                        "broadcast_packets": sent_b,
                        "gateway_unicast_packets": sent_u,
                        "claimed_identity": f"{my_ip}->{my_mac}",
                        "sustained_mode": self._sustained}
                else:
                    actions["self_assertion"] = {
                        "skipped": "per-minute packet budget reached "
                                   "(airtime guard)"}
            else:
                actions["self_assertion"] = {"skipped": "cooldown"}

            self.events.emit_simple(
                "defense.corrective_action", "notice", "confirmed",
                f"Corrective defense after {kind}: kernel gateway re-pin "
                f"{'done' if actions.get('kernel_repin', {}).get('ok') else 'skipped'}; "
                f"self-assertion: {actions.get('self_assertion', {}).get(
                    'broadcast_packets', 0)} broadcast + "
                f"{actions.get('self_assertion', {}).get(
                    'gateway_unicast_packets', 0)} unicast packet(s) "
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

    def _send_gateway_unicast(self, my_ip: str, my_mac: str,
                              gw_ip: str, gw_mac: str, count: int) -> int:
        """Send `count` UNICAST ARP replies to the gateway re-asserting
        OUR OWN identity in the gateway's ARP cache.

        NetCut's "cut the victim off" primitive poisons the gateway's
        cache about this host; a unicast reply heals exactly that cache
        while consuming a fraction of the airtime a broadcast costs.
        Same L2 construction as _send_garps (no L3 socket — see the
        crash note there). Still only ever claims OUR identity (ADR-001).
        """
        try:
            from scapy.all import sendp, Ether, ARP
            pkt = (Ether(dst=gw_mac, src=my_mac) /
                   ARP(op=2, psrc=my_ip, hwsrc=my_mac,
                       pdst=gw_ip, hwdst=gw_mac))
            sendp(pkt, count=count, inter=0.05, verbose=False)
            return count
        except Exception as e:
            log_warn(f"corrective unicast ARP to gateway failed: {e}")
            return 0
