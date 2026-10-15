"""WifiDiagnostics — connectivity failure classification + disruption correlation.

Classifies WHY connections fail (auth vs DHCP vs DNS vs signal vs driver),
correlates repeated disconnects with concurrent ARP/DHCP events (NetCut-
style local disruption inference), and probes hardware capability
(monitor mode) for deauth visibility — reporting it honestly when absent.

NEVER reconnects by itself (owner requirement: no unverified corrective
action; AGENTS.md rule 7).
"""
import re
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

from netfend.models.events import EventStore
from netfend.utils import capabilities
from netfend.utils.config import cfg
from netfend.utils.logging import log_info

_TIMEOUT = 6


def _run(cmd: List[str]) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
        return r.stdout if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------------------
# Pure parsers + classifier (unit-testable)
# ---------------------------------------------------------------------------

def parse_iw_link(output: str) -> Dict[str, Any]:
    """Parse `iw dev X link` output into {connected, ssid, rssi, tx_bitrate}."""
    info: Dict[str, Any] = {"connected": "Not connected." not in output,
                            "ssid": None, "rssi": None, "tx_bitrate": None}
    m = re.search(r"SSID:\s*(.+)", output)
    if m:
        info["ssid"] = m.group(1).strip()
    m = re.search(r"signal:\s*(-?\d+)\s*dBm", output)
    if m:
        info["rssi"] = int(m.group(1))
    m = re.search(r"tx bitrate:\s*([\d.]+)", output)
    if m:
        info["tx_bitrate"] = float(m.group(1))
    return info


def parse_nmcli_devices(output: str) -> Dict[str, Dict[str, str]]:
    """Parse `nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device` (colon-separated)."""
    out: Dict[str, Dict[str, str]] = {}
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            out[parts[0]] = {"type": parts[1], "state": parts[2],
                             "connection": ":".join(parts[3:])}
    return out


def classify_wifi_failure(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Given a connection snapshot, classify the failure mode.

    context: {assoc_state: connected|associating|disconnected,
              have_ip: bool, dns_ok: bool|None, rssi: int|None,
              retries: int}
    Returns an event dict or None (healthy).
    """
    state = context.get("assoc_state", "disconnected")
    have_ip = context.get("have_ip")
    dns_ok = context.get("dns_ok")
    rssi = context.get("rssi")
    retries = context.get("retries", 0)

    if state == "associating" and retries >= 3:
        return {"kind": "wifi.auth_failure", "severity": "warning",
                "confidence": "suspected",
                "summary": f"Repeated association/authentication failures ({retries} attempts) — wrong credentials, AP rejection, or deauth interference",
                "evidence": context}
    if state == "connected" and have_ip is False:
        return {"kind": "wifi.dhcp_failure", "severity": "warning",
                "confidence": "suspected",
                "summary": "Associated but no IP address — DHCP failure (server down, exhaustion, or rogue DHCP interference)",
                "evidence": context}
    if state == "connected" and have_ip and dns_ok is False:
        return {"kind": "wifi.dns_failure", "severity": "notice",
                "confidence": "suspected",
                "summary": "Connected with IP but DNS failing — resolver problem rather than Wi-Fi",
                "evidence": context}
    if rssi is not None and rssi <= context.get("weak_rssi", -80):
        return {"kind": "wifi.weak_signal", "severity": "notice",
                "confidence": "confirmed",
                "summary": f"Weak Wi-Fi signal ({rssi} dBm) — range/interference, not an attack",
                "evidence": context}
    return None


def classify_disconnect_pattern(disconnects: List[float], now: float,
                                count_threshold: int, window_s: float) -> Optional[Dict[str, Any]]:
    """Repeated disconnects within window => suspicious pattern event."""
    recent = [t for t in disconnects if now - t <= window_s]
    if len(recent) >= count_threshold:
        return {
            "kind": "wifi.repeated_disconnects",
            "severity": "warning",
            "confidence": "suspected",
            "summary": (f"{len(recent)} Wi-Fi disconnects within {window_s}s — "
                        f"instability, interference, or deauth attack"),
            "evidence": {"disconnect_count": len(recent),
                         "window_s": window_s,
                         "timestamps": recent}}
    return None


# ---------------------------------------------------------------------------
# WifiDiagnostics service
# ---------------------------------------------------------------------------

class WifiDiagnostics:
    def __init__(self, nm, events: EventStore):
        self.nm = nm
        self.events = events
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._state: str = "unknown"       # connected|associating|disconnected
        self._assoc_retries = 0
        self._disconnects: List[float] = []
        self._last_classified: Dict[str, float] = {}
        self.current: Dict[str, Any] = {}

    def available(self) -> bool:
        return capabilities.have("iw") or capabilities.have("nmcli")

    def start(self) -> bool:
        if not cfg("wifi", "enabled", True) or not self.available():
            self.events.emit_simple(
                "wifi.unavailable", "info", "unverified",
                "Wi-Fi diagnostics unavailable (no iw/nmcli or no wireless hardware)",
                source="wifi")
            return False
        self._thread = threading.Thread(target=self._loop, name="nf-wifi",
                                        daemon=True)
        self._thread.start()
        log_info("Wi-Fi diagnostics active")
        return True

    def _loop(self):
        interval = cfg("wifi", "poll_interval_s", 10)
        weak_rssi = cfg("wifi", "weak_signal_rssi", -80)
        while not self._stop.wait(interval):
            iface = self.nm.snapshot()["interface"]
            if not iface:
                continue
            snapshot = self._collect(iface, weak_rssi)
            self.current = snapshot
            self._on_snapshot(snapshot)

    def _collect(self, iface: str, weak_rssi: int) -> Dict[str, Any]:
        snap: Dict[str, Any] = {"interface": iface}
        iw_out = _run(["iw", "dev", iface, "link"])
        if iw_out is not None:
            snap.update(parse_iw_link(iw_out))
        nm_out = _run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
        if nm_out is not None:
            devices = parse_nmcli_devices(nm_out)
            d = devices.get(iface)
            if d:
                snap["nm_state"] = d["state"]
                snap["nm_connection"] = d["connection"]
        identity = self.nm.snapshot()
        snap["have_ip"] = bool(identity["my_ip"])
        snap["assoc_state"] = self._assoc_state(snap)
        snap["rssi"] = snap.get("rssi")
        snap["weak_rssi"] = weak_rssi
        return snap

    @staticmethod
    def _assoc_state(snap: Dict[str, Any]) -> str:
        nm_state = snap.get("nm_state")
        if nm_state == "activated" and snap.get("connected"):
            return "connected"
        if nm_state in ("activating", "configuring"):
            return "associating"
        if nm_state == "deactivating":
            return "disconnected"
        if snap.get("connected"):
            return "connected"
        if snap.get("nm_state") == "failed":
            return "associating"  # retries will be counted by transitions
        return "disconnected"

    def _on_snapshot(self, snap: Dict[str, Any]):
        now = time.time()
        new_state = snap["assoc_state"]
        # Track association retries and disconnects via state transitions
        if new_state == "associating" and self._state == "associating":
            self._assoc_retries += 1
        elif new_state == "associating":
            self._assoc_retries = 1
        if self._state == "connected" and new_state != "connected":
            self._disconnects.append(now)
            self._disconnects = self._disconnects[-50:]
        self._state = new_state

        snap["retries"] = self._assoc_retries
        snap["dns_ok"] = (self._dns_ok())
        ev = classify_wifi_failure(snap)
        if ev and self._cooldown_ok(ev["kind"], now, 300):
            self.events.emit_simple(ev["kind"], ev["severity"], ev["confidence"],
                                    ev["summary"], source="wifi",
                                    **self._safe_evidence(ev["evidence"]))
        pat = classify_disconnect_pattern(
            self._disconnects, now,
            cfg("wifi", "disconnect_count", 3),
            cfg("wifi", "disconnect_window_s", 300))
        if pat and self._cooldown_ok("wifi.repeated_disconnects", now, 600):
            # Correlate with concurrent local-network attack signals
            arp_events = self.events.count_since(now - 600, kind_prefix="arp.")
            dhcp_events = self.events.count_since(now - 600, kind_prefix="dhcp.")
            if arp_events + dhcp_events > 0:
                pat["severity"] = "critical"
                pat["confidence"] = "confirmed"
                pat["summary"] += " — correlated with ARP/DHCP anomalies (NetCut-like local disruption)"
            self.events.emit_simple(pat["kind"], pat["severity"], pat["confidence"],
                                    pat["summary"], source="wifi",
                                    arp_events_10m=arp_events,
                                    dhcp_events_10m=dhcp_events,
                                    **pat["evidence"])

    def _dns_ok(self) -> Optional[bool]:
        try:
            import socket
            socket.setdefaulttimeout(3)
            socket.getaddrinfo("example.com", None, socket.AF_INET)
            return True
        except OSError:
            return False

    @staticmethod
    def _safe_evidence(ev: Dict[str, Any]) -> Dict[str, Any]:
        keep = ("assoc_state", "have_ip", "dns_ok", "rssi", "retries",
                "interface", "nm_state")
        return {k: v for k, v in ev.items() if k in keep}

    def _cooldown_ok(self, key: str, now: float, cooldown: float) -> bool:
        if now - self._last_classified.get(key, 0.0) >= cooldown:
            self._last_classified[key] = now
            return True
        return False

    def status(self) -> Dict[str, Any]:
        caps = capabilities.probe()
        return {
            "current": self.current,
            "monitor_mode_capable": bool(caps.get("monitor_mode")),
            "deauth_detection": ("frame-level detection requires monitor mode; "
                                 "not available on this adapter — enable 802.11w/PMF "
                                 "on the router for management-frame protection"
                                 if not caps.get("monitor_mode")
                                 else "monitor mode available"),
            "available": self.available(),
        }

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
