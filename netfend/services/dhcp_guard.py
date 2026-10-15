"""DhcpGuard — rogue DHCP server and lease-option manipulation detection.

Passive: captures only DHCP server->client traffic (BPF `udp port 67`),
never transmits. Learning window (default 2 observations) prevents
false-flagging the legitimate server on first run (unknowns U-3).
"""
import threading
import time
from typing import Any, Dict, List, Optional

from netfend.models.events import EventStore
from netfend.utils import capabilities
from netfend.utils.logging import log_info, log_warn

DHCP_MESSAGE_TYPES = {1: "discover", 2: "offer", 3: "request",
                      4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}


class DhcpEvaluator:
    """Pure evaluator. Observations:
    {server_ip, server_mac, message_type (str), your_ip, options: {router, dns: [..]}}
    """

    def __init__(self):
        self.baseline_servers: Dict[str, Dict[str, Any]] = {}  # "ip|mac" -> info
        self.learn_observations = 2
        self.baseline_router: Optional[str] = None
        self.baseline_dns: List[str] = []
        self._last_rogue_emitted: Dict[str, float] = {}

    def evaluate(self, obs: Dict[str, Any], now: float) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        if obs.get("message_type") not in ("offer", "ack"):
            return events  # only server-originated messages indicate a server
        skey = f"{obs.get('server_ip')}|{obs.get('server_mac')}"

        if skey not in self.baseline_servers:
            if len(self.baseline_servers) < self.learn_observations:
                # Learning window: assume legitimate
                self.baseline_servers[skey] = {
                    "server_ip": obs.get("server_ip"),
                    "server_mac": obs.get("server_mac"),
                    "first_seen": now,
                }
                return events
            # Known servers exist and this is a NEW server => rogue candidate
            if self._cooldown_ok(skey, now, 300):
                events.append({
                    "kind": "dhcp.rogue_server",
                    "severity": "critical",
                    "confidence": "suspected",
                    "summary": (f"Unexpected DHCP server {obs.get('server_ip')} "
                                f"({obs.get('server_mac')}) offered address "
                                f"{obs.get('your_ip')} — rogue DHCP or new equipment"),
                    "evidence": {
                        "server_ip": obs.get("server_ip"),
                        "server_mac": obs.get("server_mac"),
                        "known_servers": list(self.baseline_servers.keys()),
                    }})
            return events

        # Known server: watch for option manipulation (router/DNS changes)
        opts = obs.get("options") or {}
        router = opts.get("router")
        dns = opts.get("dns") or []
        if router and self.baseline_router and router != self.baseline_router:
            if self._cooldown_ok(f"router:{router}", now, 300):
                events.append({
                    "kind": "dhcp.router_option_change",
                    "severity": "warning",
                    "confidence": "suspected",
                    "summary": (f"DHCP-assigned gateway changed "
                                f"{self.baseline_router} -> {router} "
                                f"(lease renewal, VPN, or manipulation)"),
                    "evidence": {"old": self.baseline_router, "new": router}})
        if dns and self.baseline_dns and dns != self.baseline_dns:
            if self._cooldown_ok(f"dns:{','.join(dns)}", now, 300):
                events.append({
                    "kind": "dhcp.dns_option_change",
                    "severity": "notice",
                    "confidence": "unverified",
                    "summary": f"DHCP-provided DNS servers changed to {dns}",
                    "evidence": {"old": self.baseline_dns, "new": dns}})
        if router:
            self.baseline_router = router
        if dns:
            self.baseline_dns = dns
        return events

    def _cooldown_ok(self, key: str, now: float, cooldown: float) -> bool:
        if now - self._last_rogue_emitted.get(key, 0.0) >= cooldown:
            self._last_rogue_emitted[key] = now
            return True
        return False


class DhcpGuard:
    """Adapter: scapy sniffer with BPF `udp port 67` feeding the evaluator."""

    def __init__(self, nm, events: EventStore):
        self.nm = nm
        self.events = events
        self.evaluator = DhcpEvaluator()
        self.evaluator.learn_observations = int(
            __import__("netfend.utils.config", fromlist=["cfg"]).cfg(
                "dhcp", "learn_observations", 2))
        self._sniffer = None

    def available(self) -> bool:
        return capabilities.have("scapy") and capabilities.have("root")

    def start(self) -> bool:
        if not self.available():
            self.events.emit_simple(
                "dhcp.unavailable", "notice", "unverified",
                "DHCP inspection unavailable (need scapy + root)",
                source="dhcp")
            return False
        from scapy.all import AsyncSniffer
        self._sniffer = AsyncSniffer(
            filter="udp port 67", prn=self._on_packet, store=False,
            iface=self.nm.snapshot()["interface"])
        self._sniffer.start()
        log_info("DHCP guard sniffer active")
        return True

    def _on_packet(self, packet):
        try:
            from scapy.all import DHCP, IP, Ether, BOOTP
            if not packet.haslayer(DHCP):
                return
            dhcp = packet[DHCP]
            msg_type = None
            router = None
            dns: List[str] = []
            for opt in dhcp.options:
                if not isinstance(opt, tuple):
                    continue
                k, v = opt[0], opt[1] if len(opt) > 1 else None
                if k == "message-type" and v in DHCP_MESSAGE_TYPES:
                    msg_type = DHCP_MESSAGE_TYPES[v]
                elif k == "router":
                    router = v[0] if isinstance(v, list) and v else v
                elif k == "domain_name_servers":
                    dns = list(v) if isinstance(v, list) else [v]
            obs = {
                "server_ip": packet[BOOTP].siaddr if packet.haslayer(BOOTP) else None,
                "server_mac": packet[Ether].src.lower() if packet.haslayer(Ether) else None,
                "message_type": msg_type,
                "your_ip": packet[BOOTP].yiaddr if packet.haslayer(BOOTP) else None,
                "options": {"router": router, "dns": dns},
            }
            self.process_observation(obs)
        except Exception:
            pass

    def process_observation(self, obs: Dict[str, Any]) -> List[Dict[str, Any]]:
        events = self.evaluator.evaluate(obs, time.time())
        for ev in events:
            self.events.emit_simple(
                ev["kind"], ev["severity"], ev["confidence"], ev["summary"],
                source="dhcp", **ev.get("evidence", {}))
        return events

    def status(self) -> Dict[str, Any]:
        return {
            "baseline_servers": list(self.evaluator.baseline_servers.keys()),
            "baseline_router": self.evaluator.baseline_router,
            "baseline_dns": self.evaluator.baseline_dns,
            "available": self.available(),
        }

    def stop(self):
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
