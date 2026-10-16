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

Zero-trust option-override rejection (P-33, threat model 2026-10-16):
a rogue server OR a compromised router can push a router option (3) or
DNS option (6) that steers traffic to an attacker proxy. The evaluator
now REJECTS such pushes instead of learning them:
- router option pointing anywhere other than the kernel-verified
  default gateway => `dhcp.router_override` (critical, confirmed),
  trusted baseline kept, threat intel fed, and (config
  `dhcp.drop_override_targets`) the engine drops traffic to/from the
  rogue router IP at nftables line rate
- DNS option collapsing public resolvers to a single LAN address
  => `dhcp.dns_override` (critical, suspected), baseline kept
- changes consistent with the verified gateway (reconfigs, mesh)
  keep the previous notice/warning behavior and ARE learned
"""
import ipaddress
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


def is_lan_ip(ip: Any) -> bool:
    """True for RFC1918/link-local addresses (never loopback)."""
    try:
        addr = ipaddress.ip_address(str(ip))
        return addr.is_private and not addr.is_loopback
    except ValueError:
        return False


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

        # Known server: watch for option manipulation (router/DNS changes).
        # P-33: overrides that steer traffic away from the verified gateway
        # or into a local DNS proxy are REJECTED (baseline kept); only
        # gateway-consistent changes are learned.
        opts = obs.get("options") or {}
        router = opts.get("router")
        dns = opts.get("dns") or []
        gw_ip = self.gateway.get("ip")

        if router and self.baseline_router and router != self.baseline_router:
            if gw_ip and router != gw_ip:
                # Option-3 override: the lease tries to move our default
                # route to something that is NOT the kernel-verified
                # gateway — rogue server or compromised router steering
                # traffic to an attacker proxy. REJECT (no baseline learn).
                if self._cooldown_ok(f"ovr-router:{router}", now, 300):
                    events.append({
                        "kind": "dhcp.router_override",
                        "severity": "critical",
                        "confidence": "confirmed",
                        "summary": (f"DHCP lease from {self._display_ip(obs)} tries to "
                                    f"set the default route to {router}, which is NOT "
                                    f"the verified gateway {gw_ip} — rogue DHCP or "
                                    f"compromised router steering traffic; override "
                                    f"REJECTED (trusted baseline kept)"),
                        "evidence": {
                            "server_ip": self._display_ip(obs),
                            "server_mac": obs.get("server_mac"),
                            "baseline_router": self.baseline_router,
                            "pushed_router": router,
                            "verified_gateway": gw_ip,
                        }})
                return events
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
            if self._is_dns_override(dns):
                # Option-6 override: public resolvers collapsed into a
                # single LAN address — classic local-proxy steering.
                if self._cooldown_ok(f"ovr-dns:{','.join(dns)}", now, 300):
                    events.append({
                        "kind": "dhcp.dns_override",
                        "severity": "critical",
                        "confidence": "suspected",
                        "summary": (f"DHCP lease from {self._display_ip(obs)} replaces "
                                    f"DNS servers {self.baseline_dns} with local-only "
                                    f"{dns} — traffic steering to a local proxy; "
                                    f"override REJECTED (trusted baseline kept; use "
                                    f"encrypted DNS or public resolvers)"),
                        "evidence": {
                            "server_ip": self._display_ip(obs),
                            "server_mac": obs.get("server_mac"),
                            "baseline_dns": self.baseline_dns,
                            "pushed_dns": dns,
                        }})
                return events
            if self._cooldown_ok(f"dns:{','.join(dns)}", now, 300):
                events.append({
                    "kind": "dhcp.dns_option_change",
                    "severity": "notice",
                    "confidence": "unverified",
                    "summary": f"DHCP-provided DNS servers changed to {dns}",
                    "evidence": {"old": self.baseline_dns, "new": dns}})
        self._update_option_baseline(obs)
        return events

    def _is_dns_override(self, new_dns: List[str]) -> bool:
        """True when public resolvers are being collapsed into local-only
        addresses (the local-proxy steering signature). LAN-to-LAN and
        public-to-public changes stay in the ambiguous/notice path."""
        if not new_dns or not self.baseline_dns:
            return False
        new_all_lan = all(is_lan_ip(d) for d in new_dns)
        baseline_had_public = any(not is_lan_ip(d) for d in self.baseline_dns)
        return new_all_lan and baseline_had_public

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
        if now - self._last_rogue_emitted.get(key, float("-inf")) >= cooldown:
            self._last_rogue_emitted[key] = now
            return True
        return False


class DhcpGuard:
    """Adapter: scapy sniffer with BPF `udp port 67` feeding the evaluator."""

    def __init__(self, nm, events: EventStore, intel=None,
                 on_override=None):
        self.nm = nm
        self.events = events
        self.intel = intel                 # optional ThreatIntelligence (P-33)
        self.on_override = on_override     # engine callback (drop rule, P-33)
        self.evaluator = DhcpEvaluator()
        self.evaluator.learn_observations = int(cfg("dhcp", "learn_observations", 2))
        self._sniffer = None
        self._keeper = None  # P-42: sniffer supervision across link flaps
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
        self._sniffer = self._make_sniffer(snap["interface"])
        self._sniffer.start()
        log_info("DHCP guard sniffer active")
        # P-42: keep the sniffer alive across link flaps
        from netfend.utils.sniffer_keeper import SnifferKeeper
        self._keeper = SnifferKeeper(
            self.events, self.nm, "dhcp",
            get=lambda: self._sniffer,
            build=self._make_sniffer,
            set_=self._store_sniffer)
        self._keeper.start()
        return True

    def _make_sniffer(self, iface: str):
        """Fresh DHCP sniffer bound to the given interface (P-42 restarts)."""
        from scapy.all import AsyncSniffer
        return AsyncSniffer(
            filter="udp port 67", prn=self._on_packet, store=False,
            iface=iface)

    def _store_sniffer(self, sniffer) -> None:
        self._sniffer = sniffer

    def sniffer_alive(self) -> bool:
        """Liveness for status/doctor (True when supervised and healthy)."""
        if self._sniffer is None:
            return False
        t = getattr(self._sniffer, "thread", None)
        return t is not None and t.is_alive()

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
            # P-33: overrides and rogues feed the threat intelligence
            if ev["kind"] in ("dhcp.router_override", "dhcp.dns_override",
                              "dhcp.rogue_server") and self.intel:
                mac = (ev.get("evidence", {}).get("server_mac") or "").lower()
                if mac:
                    target = (ev.get("evidence", {}).get("pushed_router")
                              or ev.get("evidence", {}).get("pushed_dns"))
                    self.intel.record_attack(mac, ev["kind"], target)
            # P-33: engine may drop the override target at line rate
            if ev["kind"] == "dhcp.router_override" and self.on_override:
                try:
                    self.on_override(ev)
                except Exception:
                    pass
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
        if self._keeper:
            self._keeper.stop()   # FIRST (P-42): no restart during teardown
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._dirty:
            self._save_baseline()
