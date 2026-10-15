"""NetworkManager — identity, routes, neighbors, passive discovery.

Rewritten per audit RC-5/RC-12 and AGENTS.md §4/§5:
- All subprocess calls use argument lists, validated inputs, timeouts.
- `ip route` parsing is defensive (point-to-point links lack `via`;
  metric clauses follow `dev`) — see docs/recovery/change-log.md T-5.
- Gateway MAC resolution happens in the BACKGROUND with retries: the
  engine starts degraded instead of dying (audit RC-12).
- Passive discovery reads the kernel neighbor table; the legacy /24 ARP
  sweep is gone (audit RC-3) except as an explicit on-demand `scan()`.
"""
import re
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from netfend.utils import capabilities
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn, log_err
from netfend.utils.validators import valid_ipv4, valid_mac, valid_interface

_TIMEOUT = 6


def _run(cmd: List[str], timeout: int = _TIMEOUT) -> Optional[str]:
    """Safe subprocess runner. Returns stdout or None on any failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return r.stdout
        return None
    except (OSError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------------------
# Pure parsers (unit-testable without a system)
# ---------------------------------------------------------------------------

def parse_default_route(route_output: str) -> Optional[Dict[str, str]]:
    """Extract (iface, gateway) from `ip route` output.

    Handles: 'default via 192.168.1.1 dev wlan0 metric 600'
             'default dev ppp0 proto kernel'        (no via)
             'default via 10.0.0.1 dev eth0 metric ...'
    """
    for line in route_output.splitlines():
        if not line.startswith("default"):
            continue
        gw, iface = None, None
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok == "via" and i + 1 < len(parts):
                gw = parts[i + 1]
            elif tok == "dev" and i + 1 < len(parts):
                iface = parts[i + 1]
        if iface:
            return {"interface": iface, "gateway": gw}
    return None


def parse_ip_addr_json(addr_json: str, interface: str) -> Optional[str]:
    """Extract first IPv4 address of `interface` from `ip -j addr` output."""
    import json
    try:
        data = json.loads(addr_json)
    except (json.JSONDecodeError, TypeError):
        return None
    for entry in data if isinstance(data, list) else []:
        if entry.get("ifname") != interface:
            continue
        for addr in entry.get("addr_info", []):
            if addr.get("family") != "inet":
                continue
            # iproute2 JSON uses "local" for the interface address
            ip = addr.get("local") or addr.get("addr")
            if ip and valid_ipv4(ip):
                return ip
    return None


def parse_neigh_output(neigh_output: str) -> List[Dict[str, str]]:
    """Parse `ip neigh` text output into [{ip, mac, dev, state}].

    Accepts both JSON (from `ip -j neigh`) and classic text.
    """
    rows: List[Dict[str, str]] = []
    stripped = neigh_output.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        import json
        try:
            data = json.loads(stripped)
            for e in data if isinstance(data, list) else []:
                ip, mac = e.get("dst"), e.get("lladdr")
                if ip and mac and valid_mac(mac):
                    rows.append({
                        "ip": ip, "mac": mac.lower(),
                        "dev": e.get("dev", ""), "state": e.get("state", ""),
                    })
            return rows
        except (json.JSONDecodeError, TypeError):
            pass
    for line in neigh_output.splitlines():
        # "192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-fA-F:]{17})\s+(\S+)",
                     line.strip())
        if m:
            rows.append({
                "ip": m.group(1), "mac": m.group(3).lower(),
                "dev": m.group(2), "state": m.group(4),
            })
    return rows


def parse_proc_net_dev(proc_net_dev: str) -> Dict[str, Dict[str, int]]:
    """Parse /proc/net/dev content into {iface: {rx_bytes, rx_packets, tx_bytes, tx_packets}}."""
    out: Dict[str, Dict[str, int]] = {}
    for line in proc_net_dev.splitlines():
        if ":" not in line:
            continue
        iface, _, rest = line.partition(":")
        iface = iface.strip()
        fields = rest.split()
        if len(fields) < 12:
            continue
        try:
            out[iface] = {
                "rx_bytes": int(fields[0]), "rx_packets": int(fields[1]),
                "tx_bytes": int(fields[8]), "tx_packets": int(fields[9]),
            }
        except ValueError:
            continue
    return out


# ---------------------------------------------------------------------------
# NetworkManager
# ---------------------------------------------------------------------------

class NetworkManager:
    """System network identity + state inspection.

    Holds no kernel state of its own; enforcement lives in FirewallManager.
    Identity attributes are refreshed via refresh() — called at start and on
    every network-change event (audit RC-5).
    """

    def __init__(self, interface: Optional[str] = None):
        self.interface: Optional[str] = interface
        self.my_ip: Optional[str] = None
        self.my_mac: Optional[str] = None
        self.gw_ip: Optional[str] = None
        self.gw_mac: Optional[str] = None
        self.link_up: bool = False
        self._identity_lock = threading.Lock()
        self._resolver_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.refresh()

    # -- detection ----------------------------------------------------------
    def _detect_default_route(self) -> Optional[Dict[str, str]]:
        out = _run(["ip", "route"])
        if out is None:
            return None
        return parse_default_route(out)

    def has_ipv6_default_route(self) -> Optional[bool]:
        """True when an IPv6 default route exists (RA/SLAAC or DHCPv6).

        Returns None when the routing table cannot be read (ip -6
        unavailable) — callers must treat None as 'unknown, do not
        suppress' (Ipv6Guard, T-32)."""
        out = _run(["ip", "-6", "route"])
        if out is None:
            return None
        return parse_default_route(out) is not None

    def refresh(self) -> bool:
        """Re-read identity from the system. Returns True when usable."""
        route = self._detect_default_route()
        with self._identity_lock:
            if route:
                if not self.interface:
                    self.interface = route["interface"]
                if route.get("gateway") and valid_ipv4(route["gateway"]):
                    self.gw_ip = route["gateway"]
                else:
                    self.gw_ip = None  # point-to-point or no default yet
            self.my_ip = self._get_my_ip()
            self.my_mac = self._get_my_mac()
            self.link_up = bool(self.my_ip)
            ok = bool(self.interface and self.my_ip)
        return ok

    # -- getters ------------------------------------------------------------
    def _get_my_ip(self) -> Optional[str]:
        if not self.interface or not capabilities.have("ip"):
            return None
        out = _run(["ip", "-j", "-4", "addr", "show", self.interface])
        if out is None:
            return None
        return parse_ip_addr_json(out, self.interface)

    def _get_my_mac(self) -> Optional[str]:
        if not self.interface:
            return None
        try:
            path = f"/sys/class/net/{self.interface}/address"
            with open(path) as f:
                mac = f.read().strip()
            return mac.lower() if valid_mac(mac) else None
        except OSError:
            return None

    def snapshot(self) -> Dict[str, Any]:
        """Identity snapshot for dashboard/CLI (thread-safe read)."""
        with self._identity_lock:
            return {
                "interface": self.interface,
                "my_ip": self.my_ip,
                "my_mac": self.my_mac,
                "gateway_ip": self.gw_ip,
                "gateway_mac": self.gw_mac,
                "link_up": self.link_up,
            }

    def set_gateway_mac(self, mac: str) -> None:
        """Thread-safe gateway MAC update (P-19: ARP guard re-baseline
        after a confirmed legitimate gateway change feeds back into the
        shared identity, so re-pinning and firewall rebuilds use it)."""
        if not (mac and valid_mac(mac)):
            return
        with self._identity_lock:
            if self.gw_mac != mac.lower():
                self.gw_mac = mac.lower()

    # -- neighbor table -----------------------------------------------------
    def get_neighbors(self) -> List[Dict[str, str]]:
        """Current kernel neighbor entries (passive discovery source)."""
        out = _run(["ip", "-j", "neigh"]) or _run(["ip", "neigh"])
        if out is None:
            return []
        return parse_neigh_output(out)

    def resolve_mac_background(self, interval: float = 5.0) -> None:
        """Start background gateway MAC resolution with retries (audit RC-12).

        Never blocks startup; retries forever until resolved or stopped.
        """
        if self._resolver_thread and self._resolver_thread.is_alive():
            return

        def _worker():
            while not self._stop_event.is_set() and not self.gw_mac:
                mac = self.resolve_mac(self.gw_ip)
                if mac:
                    with self._identity_lock:
                        self.gw_mac = mac
                    log_info(f"Gateway {self.gw_ip} resolved to MAC {mac}")
                    return
                self._stop_event.wait(interval)

        self._resolver_thread = threading.Thread(
            target=_worker, name="nf-gw-resolver", daemon=True)
        self._resolver_thread.start()

    def resolve_mac(self, ip: Optional[str], timeout: float = 2.0) -> Optional[str]:
        """Resolve MAC for IP. Prefers kernel neighbor table; falls back to
        a single ARP request via scapy when available. Bounded time."""
        if not ip or not valid_ipv4(ip):
            return None
        # 1) Kernel already knows?
        for n in self.get_neighbors():
            if n["ip"] == ip and n["state"] != "FAILED":
                return n["mac"]
        # 2) Ask via scapy (single request, no retry storm)
        if capabilities.have("scapy"):
            try:
                from scapy.all import Ether, ARP, srp, conf
                old_iface = conf.iface
                if self.interface and valid_interface(self.interface):
                    conf.iface = self.interface
                try:
                    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                                timeout=timeout, retry=0, verbose=False)
                    for _, rcv in ans:
                        return rcv[Ether].src.lower()
                finally:
                    conf.iface = old_iface
            except Exception as e:
                log_warn(f"scapy MAC resolution failed: {e}")
        return None

    # -- static neighbor entries (kernel ARP pinning) ------------------------
    def set_static_neighbor(self, ip: str, mac: str) -> bool:
        """Pin ip->mac in the kernel neighbor table (protects THIS host from
        ARP poisoning for that destination; ADR-002)."""
        if not (valid_ipv4(ip) and valid_mac(mac) and self.interface):
            return False
        r = subprocess.run(
            ["ip", "neigh", "replace", ip, "lladdr", mac.lower(),
             "dev", self.interface, "nud", "permanent"],
            capture_output=True, timeout=_TIMEOUT)
        return r.returncode == 0

    def remove_static_neighbor(self, ip: str) -> bool:
        """Remove a static/pinned neighbor entry (cleanup on stop/change)."""
        if not (valid_ipv4(ip) and self.interface):
            return False
        r = subprocess.run(
            ["ip", "neigh", "del", ip, "dev", self.interface],
            capture_output=True, timeout=_TIMEOUT)
        return r.returncode == 0

    # -- on-demand active scan (explicit user action only) -------------------
    def scan(self, timeout: float = 1.5) -> List[Tuple[str, str]]:
        """Explicit ARP scan of the local /24. NEVER called periodically
        (audit RC-3). Used by `netfend scan` and dashboard 'wifi-rescan'."""
        if not self.my_ip or not capabilities.have("scapy"):
            # Fallback: passive neighbor read
            return [(n["ip"], n["mac"]) for n in self.get_neighbors()]
        try:
            from scapy.all import Ether, ARP, srp, conf
            prefix = ".".join(self.my_ip.split(".")[:3])
            ips = [f"{prefix}.{i}" for i in range(1, 255) if f"{prefix}.{i}" != self.my_ip]
            old_iface = conf.iface
            if valid_interface(self.interface or ""):
                conf.iface = self.interface
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips),
                             timeout=timeout, retry=0, verbose=False)
                return [(rcv[ARP].psrc, rcv[ARP].hwsrc.lower()) for _, rcv in ans]
            finally:
                conf.iface = old_iface
        except Exception as e:
            log_err(f"active scan failed: {e}")
            return []

    def stop(self) -> None:
        self._stop_event.set()
        if self._resolver_thread:
            self._resolver_thread.join(timeout=2)
