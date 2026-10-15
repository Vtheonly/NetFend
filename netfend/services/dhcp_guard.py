"""DhcpGuard — rogue DHCP server and lease-option manipulation detection.

Passive: captures only DHCP server->client traffic (BPF `udp port 67`),
never transmits. Learning window (default 2 observations) prevents
false-flagging the legitimate server on first run (unknowns U-3).

Field-tested fixes (live report 2026-10-15, problem P-23):
- 'Unexpected DHCP server 0.0.0.0 (1c:73:e2:57:f1:39)' was flagged
  CRITICAL. Root causes: the BOOTP siaddr field is routinely 0.0.0.0
  (many servers fill only option 54), and a mesh node answering DHCP for
  the primary router is legitimate infrastructure, not a rogue. Now:
  * server identity prefers DHCP option 54 (server identifier), falls
    back to siaddr, and never keys on 0.0.0.0
  * a server whose identifier equals the current gateway IP and whose
    router option points at the same gateway is classified as
    infrastructure (notice, not critical) — mesh node or router
  * baselines persist to DATA_DIR/dhcp_baseline.json so engine restarts
    stop re-learning (and re-flagging) the same known servers
"""
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from netfend.models.events import EventStore
from netfend.utils import capabilities
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn

DHCP_MESSAGE_TYPES = {1: "discover", 2: "offer", 3: "request",
                      4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}

_UNSET_IPS = ("", "0.0.0.0", None)


class DhcpEvaluator:
    """Pure evaluator. Observations:
    {server_ip, server_mac, message_type (str), your_ip,
     options: {router, dns: [..], server_id}}
    `gateway` context: {"ip": ..., "macs": [trusted, ...]} — used for
    infrastructure correlation (P-23).
    """

    def __init__(self, gateway: Optional[Dict[str, Any]] = None):
        self.baseline_servers: Dict[str, Dict[str, Any]] = {}  # "ip|mac" -> info
        self.learn_observations = 2
        self._observations_seen = 0   # total server messages during learning
        self.baseline_router: Optional[str] = None
        self.baseline_dns: List[str] = []
        self._last_rogue_emitted: Dict[str, float] = {}
        self.gateway = gateway or {}

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def server_key(obs: Dict[str, Any]) -> str:
        """Stable identity for a DHCP server.

        Prefers option 54 (server identifier); falls back to siaddr; a
        0.0.0.0/unset identifier keys on the MAC alone (P-23: keying on
        '0.0.0.0' made every renewal look like a different server).
        """
        server_id = obs.get("options", {}).get("server_id") or obs.get("server_ip")
        mac = (obs.get("server_mac") or "").lower()
        if server_id in _UNSET_IPS:
            return f"|{mac}"
        return f"{server_id}|{mac}"

    def _is_infrastructure(self, obs: Dict[str, Any]) -> bool:
        """A server identifying itself as the current gateway AND handing
        out that same gateway as the router option is infrastructure
        (primary router or mesh node proxying it) — not a rogue."""
        gw_ip = self.gateway.get("ip")
        if not gw_ip:
            return False
        server_id = obs.get("options", {}).get("server_id") or obs.get("server_ip")
        router = (obs.get("options") or {}).get("router")
        return server_id == gw_ip and router == gw_ip

    # -- evaluation ------------------------------------------------------------
    def evaluate(self, obs: Dict[str, Any], now: float) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        if obs.get("message_type") not in ("offer", "ack"):
            return events  # only server-originated messages indicate a server
        skey = self.server_key(obs)

        # Learning window counts OBSERVATIONS (not distinct servers), so a
        # single server seen twice completes a learn_observations=2 window.
        if self._observations_seen < self.learn_observations:
            self._observations_seen += 1
            self.baseline_servers.setdefault(skey, {
                "server_ip": self._display_ip(obs),
                "server_mac": obs.get("server_mac"),
                "first_seen": now,
                "classification": "infrastructure" if self._is_infrastructure(obs)
                                  else "unknown",
            })
            self._update_option_baseline(obs)
            return events

        if skey not in self.baseline_servers:
            # Known servers exist and this is a NEW server => rogue candidate
            if self._is_infrastructure(obs):
                # P-23: mesh node / router answering under the gateway
                # identity — legitimate in mesh deployments; record + notice
                if self._cooldown_ok(skey, now, 300):
                    self.baseline_servers[skey] = {
                        "server_ip": self._display_ip(obs),
                        "server_mac": obs.get("server_mac"),
                        "first_seen": now,
                        "classification": "infrastructure",
                    }
                    events.append({
                        "kind": "dhcp.infra_server",
                        "severity": "notice",
                        "confidence": "confirmed",
                        "summary": (f"DHCP server {self._display_ip(obs)} "
                                    f"({obs.get('server_mac')}) matches the gateway "
                                    f"identity — mesh node or router; learned as "
                                    f"known infrastructure"),
                        "evidence": {
                            "server_ip": self._display_ip(obs),
                            "server_mac": obs.get("server_mac"),
                            "known_servers": list(self.baseline_servers.keys()),
                        }})
                self._update_option_baseline(obs)
                return events
            if self._cooldown_ok(skey, now, 300):
                events.append({
                    "kind": "dhcp.rogue_server",
                    "severity": "critical",
                    "confidence": "suspected",
                    "summary": (f"Unexpected DHCP server {self._display_ip(obs)} "
                                f"({obs.get('server_mac')}) offered address "
                                f"{obs.get('your_ip')} — rogue DHCP or new equipment"),
                    "evidence": {
                        "server_ip": self._display_ip(obs),
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
        self._update_option_baseline(obs)
        return events

    # -- persistence (P-23) ------------------------------------------------------
    @staticmethod
    def _display_ip(obs: Dict[str, Any]) -> Any:
        return (obs.get("options", {}).get("server_id")
                or obs.get("server_ip") or "unknown")

    def to_persist(self) -> Dict[str, Any]:
        return {
            "baseline_servers": {k: v for k, v in self.baseline_servers.items()},
            "baseline_router": self.baseline_router,
            "baseline_dns": self.baseline_dns,
        }

    def load_persisted(self, data: Dict[str, Any]) -> None:
        servers = data.get("baseline_servers") or {}
        if isinstance(servers, dict):
            self.baseline_servers.update(servers)
        if data.get("baseline_router"):
            self.baseline_router = data["baseline_router"]
        if data.get("baseline_dns"):
            self.baseline_dns = list(data["baseline_dns"])
        # persisted baselines count as completed learning
        if self.baseline_servers:
            self._observations_seen = self.learn_observations

    def _update_option_baseline(self, obs: Dict[str, Any]) -> None:
        opts = obs.get("options") or {}
        if opts.get("router"):
            self.baseline_router = opts["router"]
        if opts.get("dns"):
            self.baseline_dns = list(opts["dns"])

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
        self.evaluator.learn_observations = int(cfg("dhcp", "learn_observations", 2))
        self._sniffer = None
        self._persist_path: Optional[Path] = None
        self._dirty = False
        self._load_baseline()

    def available(self) -> bool:
        return capabilities.have("scapy") and capabilities.have("root")

    # -- baseline persistence (P-23) ------------------------------------------
    def _baseline_path(self) -> Path:
        from netfend.utils.config import DATA_DIR
        return Path(DATA_DIR) / "dhcp_baseline.json"

    def _load_baseline(self):
        try:
            p = self._persist_path or self._baseline_path()
            if p.exists():
                with open(p, "r") as f:
                    self.evaluator.load_persisted(json.load(f))
                if self.evaluator.baseline_servers:
                    log_info(f"DHCP baselines loaded: "
                             f"{len(self.evaluator.baseline_servers)} server(s)")
        except (OSError, json.JSONDecodeError, ValueError) as e:
            log_warn(f"Could not load DHCP baseline: {e}")

    def _save_baseline(self):
        try:
            p = self._persist_path or self._baseline_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w") as f:
                json.dump(self.evaluator.to_persist(), f, indent=2)
        except OSError as e:
            log_warn(f"Could not save DHCP baseline: {e}")

    def start(self) -> bool:
        if not self.available():
            self.events.emit_simple(
                "dhcp.unavailable", "notice", "unverified",
                "DHCP inspection unavailable (need scapy + root)",
                source="dhcp")
            return False
        # refresh gateway context for infrastructure correlation
        snap = self.nm.snapshot()
        self.evaluator.gateway = {"ip": snap.get("gateway_ip"),
                                  "macs": [snap.get("gateway_mac")] if snap.get("gateway_mac") else []}
        from scapy.all import AsyncSniffer
        self._sniffer = AsyncSniffer(
            filter="udp port 67", prn=self._on_packet, store=False,
            iface=snap["interface"])
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
            server_id = None
            for opt in dhcp.options:
                if not isinstance(opt, tuple):
                    continue
                k, v = opt[0], opt[1] if len(opt) > 1 else None
                if k == "message-type" and v in DHCP_MESSAGE_TYPES:
                    msg_type = DHCP_MESSAGE_TYPES[v]
                elif k == "router":
                    router = v[0] if isinstance(v, list) and v else v
                elif k == "server_id":
                    server_id = v
                elif k == "domain_name_servers":
                    dns = list(v) if isinstance(v, list) else [v]
            obs = {
                "server_ip": packet[BOOTP].siaddr if packet.haslayer(BOOTP) else None,
                "server_mac": packet[Ether].src.lower() if packet.haslayer(Ether) else None,
                "message_type": msg_type,
                "your_ip": packet[BOOTP].yiaddr if packet.haslayer(BOOTP) else None,
                "options": {"router": router, "dns": dns, "server_id": server_id},
            }
            self.process_observation(obs)
        except Exception:
            pass

    def process_observation(self, obs: Dict[str, Any]) -> List[Dict[str, Any]]:
        # keep gateway context fresh (roaming changes it)
        try:
            snap = self.nm.snapshot()
            self.evaluator.gateway = {
                "ip": snap.get("gateway_ip"),
                "macs": [snap.get("gateway_mac")] if snap.get("gateway_mac") else []}
        except Exception:
            pass
        before = set(self.evaluator.baseline_servers)
        events = self.evaluator.evaluate(obs, time.time())
        for ev in events:
            self.events.emit_simple(
                ev["kind"], ev["severity"], ev["confidence"], ev["summary"],
                source="dhcp", **ev.get("evidence", {}))
        if set(self.evaluator.baseline_servers) != before:
            self._dirty = True
            self._save_baseline()  # debounced enough: only on new servers
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
        if self._dirty:
            self._save_baseline()
