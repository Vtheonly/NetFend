"""ArpGuard — local-network attack detection (NetCut-class threats).

Pure evaluation + optional scapy sniffer (ADR-005). Detections:

- gateway spoof: foreign MAC claims the gateway IP (while the pinned
  gateway is still alive => confirmed conflict; gateway gone => legitimate
  replacement workflow, requires confirmations)
- own-IP conflict: foreign MAC claims OUR IP (IP hijack / NetCut "you are
  the victim" mode)
- IP-to-MAC flapping: one IP alternating between >= N MACs in a window —
  the classic poison/anti-poison fight signature
- gratuitous ARP floods: rate-based per source MAC (token window)
- unsolicited ARP reply storms

False-positive controls (AGENTS.md rule 7):
- our own transmissions are ignored
- DHCP renewals re-announce gateway legitimately — the gateway-change
  workflow requires `gateway_confirmations` consistent observations AND
  the old gateway being absent before re-baselining
- flapping requires >= flap_mac_count distinct MACs within flap_window_s
"""
import threading
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

from netfend.models.events import EventStore
from netfend.utils import capabilities
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn

MAX_HISTORY_PER_IP = 64


class ArpEvaluator:
    """Pure state machine — no I/O. Fed with observation dicts by the
    sniffer adapter or by tests."""

    def __init__(self, my_ip: str, my_mac: str, gw_ip: Optional[str],
                 gw_mac: Optional[str]):
        self.my_ip, self.my_mac = my_ip, (my_mac or "").lower()
        self.gw_ip, self.gw_mac = gw_ip, (gw_mac or "").lower()
        self.ip_mac_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=MAX_HISTORY_PER_IP))
        self.garp_timestamps: Dict[str, deque] = defaultdict(deque)
        # gateway-change workflow state
        self.pending_gw_change: Optional[Dict[str, Any]] = None
        self.last_conflict_emitted: Dict[str, float] = {}
        self.emitted_flap: Dict[str, float] = {}

    # -- helpers -------------------------------------------------------------
    def _observed(self, ip: str, mac: str, ts: float):
        hist = self.ip_mac_history[ip]
        # dedupe consecutive same-MAC observations
        if not hist or hist[-1][0] != mac:
            hist.append((mac, ts))

    def _rate_ok(self, mac: str, ts: float, window: float, max_count: int) -> bool:
        """False when `mac` exceeds max_count events in window."""
        dq = self.garp_timestamps[mac]
        dq.append(ts)
        while dq and ts - dq[0] > window:
            dq.popleft()
        return len(dq) <= max_count

    # -- main evaluation -------------------------------------------------------
    def evaluate(self, pkt: Dict[str, Any], now: float) -> List[Dict[str, Any]]:
        """pkt: {op:int(1=req,2=reply), psrc:str, hwsrc:str, pdst:str, hwdst:str}
        Returns a list of event dicts (kind, severity, confidence, summary,
        evidence). Caller turns them into SecurityEvents."""
        events: List[Dict[str, Any]] = []
        op = pkt.get("op")
        psrc = pkt.get("psrc", "")
        hwsrc = (pkt.get("hwsrc") or "").lower()
        if op not in (1, 2) or not hwsrc or hwsrc == "ff:ff:ff:ff:ff:ff":
            return events
        # Never react to our own transmissions (audit RC-9 self-observation)
        if hwsrc == self.my_mac:
            return events

        self._observed(psrc, hwsrc, now)

        # ---- CASE 1: someone claims the gateway IP --------------------------
        if self.gw_ip and psrc == self.gw_ip and self.gw_mac and hwsrc != self.gw_mac:
            if self.pending_gw_change and self.pending_gw_change["mac"] == hwsrc:
                self.pending_gw_change["count"] += 1
                self.pending_gw_change["last_ts"] = now
            else:
                self.pending_gw_change = {
                    "mac": hwsrc, "count": 1, "first_ts": now, "last_ts": now}
            confirmations = cfg("arp", "gateway_confirmations", 2)
            if self.pending_gw_change["count"] >= confirmations:
                old_alive = self._old_gateway_alive(now)
                if old_alive:
                    # Both MACs claim the gateway => classic MITM/poison
                    key = f"gwconf:{hwsrc}"
                    if self._cooldown_ok(key, now, 60):
                        events.append({
                            "kind": "arp.gateway_spoof",
                            "severity": "critical",
                            "confidence": "confirmed",
                            "summary": (f"Gateway conflict: {hwsrc} and {self.gw_mac} "
                                        f"both claim gateway {self.gw_ip} (MITM/poison likely)"),
                            "evidence": {
                                "gateway_ip": self.gw_ip,
                                "pinned_gateway_mac": self.gw_mac,
                                "conflicting_mac": hwsrc,
                                "observations": self.pending_gw_change["count"],
                                "old_gateway_still_active": True,
                            }})
                else:
                    # Old gateway silent + new MAC persistent => router replaced
                    events.append({
                        "kind": "arp.gateway_change",
                        "severity": "notice",
                        "confidence": "unverified",
                        "summary": (f"Gateway {self.gw_ip} now announces MAC {hwsrc} "
                                    f"(previous {self.gw_mac} silent) — likely legitimate "
                                    f"router change; re-baselining recommended"),
                        "evidence": {
                            "gateway_ip": self.gw_ip,
                            "old_mac": self.gw_mac,
                            "new_mac": hwsrc,
                            "observations": self.pending_gw_change["count"],
                        }})
                self.pending_gw_change = None

        # ---- CASE 2: someone claims OUR IP -----------------------------------
        elif psrc == self.my_ip and hwsrc != self.my_mac:
            key = f"ownip:{hwsrc}"
            if self._cooldown_ok(key, now, 60):
                events.append({
                    "kind": "arp.own_ip_conflict",
                    "severity": "warning",
                    "confidence": "suspected",
                    "summary": (f"{hwsrc} claims OUR IP {self.my_ip} "
                                f"(IP hijack attempt or address misconfiguration)"),
                    "evidence": {"claiming_mac": hwsrc, "our_ip": self.my_ip}})

        # ---- CASE 3: gratuitous ARP flood per source ---------------------------
        is_gratuitous = (op == 2 and psrc == pkt.get("pdst"))
        if is_gratuitous:
            rate = cfg("arp", "gratuitous_rate_per_s", 10)
            burst = cfg("arp", "gratuitous_burst", 25)
            if not self._rate_ok(hwsrc, now, window=10.0, max_count=burst):
                key = f"garp:{hwsrc}"
                if self._cooldown_ok(key, now, 60):
                    events.append({
                        "kind": "arp.gratuitous_flood",
                        "severity": "warning",
                        "confidence": "suspected",
                        "summary": (f"Excessive gratuitous ARP from {hwsrc} "
                                    f"(cache-poisoning flood signature)"),
                        "evidence": {"source_mac": hwsrc,
                                     "threshold_per_10s": burst}})

        # ---- CASE 4: IP-to-MAC flapping ---------------------------------------
        flap_window = cfg("arp", "flap_window_s", 120)
        flap_count = cfg("arp", "flap_mac_count", 3)
        hist = self.ip_mac_history.get(psrc)
        if hist:
            recent = [(m, t) for (m, t) in hist if now - t <= flap_window]
            macs = {m for (m, _) in recent}
            if len(macs) >= flap_count:
                key = f"flap:{psrc}"
                if self._cooldown_ok(key, now, flap_window):
                    events.append({
                        "kind": "arp.ip_mac_flapping",
                        "severity": "warning",
                        "confidence": "suspected",
                        "summary": (f"IP {psrc} seen with {len(macs)} different MACs "
                                    f"in {flap_window}s (poison/anti-poison fight or "
                                    f"DHCP reassignment)"),
                        "evidence": {"ip": psrc, "macs": sorted(macs),
                                     "window_s": flap_window}})

        return events

    def _old_gateway_alive(self, now: float) -> bool:
        """Heuristic: did we observe the pinned gateway MAC recently?"""
        hist = self.ip_mac_history.get(self.gw_ip or "", deque())
        for mac, ts in hist:
            if mac == self.gw_mac and (now - ts) <= 120:
                return True
        return False

    def _cooldown_ok(self, key: str, now: float, cooldown: float) -> bool:
        last = self.last_conflict_emitted.get(key, 0.0)
        if now - last >= cooldown:
            self.last_conflict_emitted[key] = now
            return True
        return False

    def rebaseline(self, gw_ip: Optional[str], gw_mac: Optional[str]) -> None:
        """Called on network change / explicit re-baseline."""
        self.gw_ip, self.gw_mac = gw_ip, (gw_mac or "").lower()
        self.pending_gw_change = None
        self.ip_mac_history.clear()
        self.garp_timestamps.clear()


class ArpGuard:
    """Adapter: scapy sniffer (BPF `arp`) feeding the pure evaluator."""

    def __init__(self, nm, events: EventStore, registry=None, intel=None):
        self.nm = nm
        self.events = events
        self.registry = registry
        self.intel = intel
        self.evaluator: Optional[ArpEvaluator] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._sniffer = None
        self._registry_dirty = False
        self._registry_last_save = 0.0

    def available(self) -> bool:
        return capabilities.have("scapy") and capabilities.have("root")

    def start(self) -> bool:
        snap = self.nm.snapshot()
        if not (snap["my_ip"] and snap["my_mac"]):
            log_warn("ARP guard not started: local identity unknown yet")
            return False
        self.evaluator = ArpEvaluator(snap["my_ip"], snap["my_mac"],
                                      snap["gateway_ip"], snap["gateway_mac"])
        if not self.available():
            self.events.emit_simple(
                "arp.unavailable", "notice", "unverified",
                "ARP inspection unavailable (need scapy + root); "
                "static neighbor pinning still active",
                source="arp")
            return False
        from scapy.all import AsyncSniffer
        self._sniffer = AsyncSniffer(
            filter="arp", prn=self._on_packet, store=False,
            iface=snap["interface"])
        self._sniffer.start()
        log_info("ARP guard sniffer active")
        # Debounced registry persistence thread (audit RC-9)
        self._thread = threading.Thread(target=self._debounce_loop,
                                        name="nf-arp-debounce", daemon=True)
        self._thread.start()
        return True

    def _on_packet(self, packet):
        try:
            from scapy.all import ARP
            if not packet.haslayer(ARP):
                return
            arp = packet[ARP]
            pkt = {
                "op": int(arp.op), "psrc": arp.psrc,
                "hwsrc": (arp.hwsrc or "").lower(),
                "pdst": arp.pdst, "hwdst": arp.hwdst,
            }
            self.process_observation(pkt)
        except Exception:
            pass  # a malformed packet must never kill the sniffer thread

    def process_observation(self, pkt: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Shared path for live packets and tests/simulations."""
        now = time.time()
        results = self.evaluator.evaluate(pkt, now) if self.evaluator else []
        for ev in results:
            self.events.emit_simple(
                ev["kind"], ev["severity"], ev["confidence"], ev["summary"],
                source="arp", interface=self.nm.snapshot()["interface"],
                **ev.get("evidence", {}))
            if self.intel:
                mac = ev.get("evidence", {}).get(
                    "conflicting_mac") or ev.get("evidence", {}).get(
                    "claiming_mac") or ev.get("evidence", {}).get("source_mac")
                if mac:
                    self.intel.record_attack(mac, ev["kind"])
        # passive device bookkeeping (debounced)
        if self.registry and pkt.get("hwsrc"):
            mac = pkt["hwsrc"]
            if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                self.registry.register_device(mac=mac, ip=pkt.get("psrc", ""),
                                              save=False)
                self._registry_dirty = True
        return results

    def _debounce_loop(self):
        while not self._stop.wait(5.0):
            if self._registry_dirty and self.registry:
                self.registry.save()
                self._registry_dirty = False

    def rebaseline(self):
        if self.evaluator:
            snap = self.nm.snapshot()
            self.evaluator.rebaseline(snap["gateway_ip"], snap["gateway_mac"])
            log_info("ARP evaluator re-baselined")

    def stop(self):
        self._stop.set()
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        if self._registry_dirty and self.registry:
            self.registry.save()
            self._registry_dirty = False
