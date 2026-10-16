"""WifiDiagnostics — connectivity failure classification + disruption correlation.

classifies WHY connections fail (auth vs DHCP vs DNS vs signal vs driver),
correlates repeated disconnects with concurrent ARP/DHCP events (NetCut-
style local disruption inference), and probes hardware capability
(monitor mode) for deauth visibility — reporting it honestly when absent.

Deauth-signature detection (P-43, live incident 2026-10-16): the owner
reset his router (new admin + Wi-Fi passwords, WPS off) and was STILL
cut off within ~17 min — slow phase, then blocked, only his device —
while other devices worked. That is the wireless-layer deauth flood
signature: forged deauth/disassociation frames spoofing the AP need
ZERO network access, so no password change stops them. Frame-level
detection needs monitor mode (P-14), but the *supplicant* sees the
effect with reason codes: repeated CTRL-EVENT-DISCONNECTED with
locally_generated=0 (the frame arrived FROM the AP — genuine or
forged, an AP that owns the network does not spam these) and reason
in {1, 2, 7} (the classic forged-deauth codes) is the fingerprint.
SupplicantMonitor reads those lines from the journal and raises
wifi.deauth_signature with the honest fix list (802.11w/PMF, WPA3,
5 GHz) — never feeding the AP's MAC into threat intel (it is the
victim's own router, P-43 trap).

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
from netfend.utils.logging import log_info, log_warn

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


# P-43: wpa_supplicant disconnect line (stable format across versions;
# locally_generated is absent on older supplicants -> None = unknown)
_RE_DISCONNECT = re.compile(
    r"CTRL-EVENT-DISCONNECTED\s+bssid=([0-9a-fA-F:]{17})\s+reason=(\d+)"
    r"(?:\s+locally_generated=(\d))?")

# Reason codes seen in forged-deauth floods (the sender picks the code;
# these are what aireplay/mdk4-class tools produce): 1 unspecified,
# 2 previous authentication no longer valid, 7 class-3 frame from a
# nonassociated station.
_FORGED_DEAUTH_REASONS = (1, 2, 7)


def parse_supplicant_disconnect(line: str) -> Optional[Dict[str, Any]]:
    """Parse a wpa_supplicant CTRL-EVENT-DISCONNECTED line.

    Returns {bssid, reason, locally_generated} or None. locally_generated
    is None on supplicants that predate the field.
    """
    m = _RE_DISCONNECT.search(line)
    if not m:
        return None
    return {"bssid": m.group(1).lower(),
            "reason": int(m.group(2)),
            "locally_generated": (int(m.group(3))
                                  if m.group(3) is not None else None)}


def parse_journal_line(line: str) -> Optional[tuple]:
    """Parse `journalctl -o short-unix` output: '<epoch> host ident[pid]: msg'.

    Returns (epoch_float, message) or None when the line has no epoch
    prefix (defensive: malformed / non-journal output must never crash
    the monitor).
    """
    parts = line.split(" ", 1)
    try:
        ts = float(parts[0])
    except (ValueError, IndexError):
        return None
    return ts, (parts[1] if len(parts) > 1 else "")


def classify_deauth_signature(observations: List[Dict[str, Any]], now: float,
                              threshold: int = 4,
                              window_s: float = 180.0) -> Optional[Dict[str, Any]]:
    """P-43: forged-deauth flood fingerprint from supplicant observations.

    Signature: >= threshold disconnects within window_s where
    locally_generated == 0 (the deauth ARRIVED from the AP — genuine or
    forged) and reason in _FORGED_DEAUTH_REASONS. A healthy AP does not
    hammer one client with these; an attacker spoofing the AP does.
    Client-initiated leaves (locally_generated=1, e.g. roaming, beacon
    loss give-ups, NM policy) never count — that is the false-positive
    guard that separates this from plain disconnect counting.

    Confidence stays 'suspected': without PMF the client cannot
    cryptographically distinguish a forged AP frame from a real one —
    the event says what was measured, not more.
    """
    incoming = [o for o in observations
                if now - o.get("ts", 0) <= window_s
                and o.get("locally_generated") == 0
                and o.get("reason") in _FORGED_DEAUTH_REASONS]
    if len(incoming) < threshold:
        return None
    reasons: Dict[int, int] = {}
    for o in incoming:
        reasons[o["reason"]] = reasons.get(o["reason"], 0) + 1
    bssids = sorted({o["bssid"] for o in incoming if o.get("bssid")})
    reason_txt = ", ".join(f"reason {r} x{c}" for r, c in sorted(reasons.items()))
    return {
        "kind": "wifi.deauth_signature",
        "severity": "critical",
        "confidence": "suspected",
        "summary": (f"Deauth flood signature: {len(incoming)} AP-addressed "
                    f"disconnects in {window_s:.0f}s ({reason_txt}) — forged "
                    f"management frames spoofing the AP (wireless attack, "
                    f"needs NO network access; password changes do not stop "
                    f"it). Mitigation: enable 802.11w/PMF (ideally Required) "
                    f"+ WPA3-SAE on the router, prefer 5 GHz for this client"),
        "evidence": {"incoming_disconnects": len(incoming),
                     "window_s": window_s,
                     "reason_counts": {str(k): v for k, v in reasons.items()},
                     "bssids": bssids,
                     "note": ("bssid is the (spoofed) AP address — never added "
                              "to threat intel; PMF would make these frames "
                              "verifiable and droppable")},
    }


# ---------------------------------------------------------------------------
# SupplicantMonitor — wpa_supplicant reason-code watch (P-43)
# ---------------------------------------------------------------------------

_MAX_OBSERVATIONS = 200
_MAX_CONSECUTIVE_FAILURES = 5


class SupplicantMonitor:
    """Read wpa_supplicant disconnects (with reason codes) from the journal.

    wpa_supplicant's CTRL-EVENT-DISCONNECTED lines are the only client-
    side record of WHY the link dropped (reason= + locally_generated=).
    Polling is bounded by --since (one poll interval of journal at a
    time) and failure-bounded (5 consecutive journalctl errors stop the
    monitor with one notice — never a crash loop). Duplicates are
    filtered by an ingest watermark (journal timestamps have
    microsecond resolution).
    """

    def __init__(self, events: EventStore):
        self.events = events
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._watermark = 0.0          # highest journal ts already ingested
        self._observations: List[Dict[str, Any]] = []
        self._failures = 0
        self._last_emitted: Dict[str, float] = {}
        self.active = False

    def start(self) -> bool:
        if not cfg("wifi", "supplicant_monitor", True):
            return False
        if (not capabilities.have("journalctl")
                or _run(["journalctl", "--version"]) is None):
            self.events.emit_simple(
                "wifi.supplicant_unavailable", "info", "unverified",
                "wpa_supplicant reason-code watch unavailable (no journalctl "
                "or no readable journal) — deauth-signature detection "
                "(wifi.deauth_signature) disabled; state-transition counters "
                "only", source="wifi")
            return False
        self._watermark = time.time()   # only events from engine start on
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="nf-supplicant",
                                        daemon=True)
        self._thread.start()
        self.active = True
        log_info("wpa_supplicant reason-code watch active (deauth signature)")
        return True

    def _loop(self):
        interval = float(cfg("wifi", "supplicant_poll_s", 5))
        while not self._stop.wait(interval):
            ok = self._poll_once()
            self._failures = 0 if ok else self._failures + 1
            if self._failures >= _MAX_CONSECUTIVE_FAILURES:
                self.active = False
                log_warn("Supplicant monitor stopping: journalctl keeps failing")
                self.events.emit_simple(
                    "wifi.supplicant_monitor_stopped", "notice", "unverified",
                    "wpa_supplicant reason-code watch stopped (journalctl "
                    "repeatedly failed); deauth-signature detection offline",
                    source="wifi")
                return

    def _poll_once(self) -> bool:
        """One bounded journal read. Returns True when the query worked."""
        since = max(0.0, self._watermark - 1.0)
        out = _run(["journalctl", "-t", "wpa_supplicant", "-u", "NetworkManager",
                    "--since", f"@{since:.6f}", "-o", "short-unix", "--no-pager"])
        if out is None:
            return False
        for line in out.splitlines():
            parsed = parse_journal_line(line)
            if parsed is None:
                continue
            ts, msg = parsed
            if ts <= self._watermark:
                continue               # already ingested (overlap window)
            d = parse_supplicant_disconnect(msg)
            if d is not None:
                d["ts"] = ts
                self._observations.append(d)
                self._watermark = ts
        self._observations = self._observations[-_MAX_OBSERVATIONS:]
        now = time.time()
        ev = classify_deauth_signature(
            self._observations, now,
            int(cfg("wifi", "deauth_threshold", 4)),
            float(cfg("wifi", "deauth_window_s", 180)))
        if ev and self._cooldown_ok(ev["kind"], now, 600):
            self.events.emit_simple(
                ev["kind"], ev["severity"], ev["confidence"], ev["summary"],
                source="wifi", **ev["evidence"])
        return True

    def _cooldown_ok(self, key: str, now: float, cooldown: float) -> bool:
        if now - self._last_emitted.get(key, 0.0) >= cooldown:
            self._last_emitted[key] = now
            return True
        return False

    def status(self) -> Dict[str, Any]:
        now = time.time()
        window = float(cfg("wifi", "deauth_window_s", 180))
        incoming = [o for o in self._observations
                    if now - o.get("ts", 0) <= window
                    and o.get("locally_generated") == 0
                    and o.get("reason") in _FORGED_DEAUTH_REASONS]
        return {"active": self.active,
                "observations_kept": len(self._observations),
                "incoming_deauth_disconnects": len(incoming)}

    def stop(self):
        self._stop.set()
        self.active = False
        if self._thread:
            self._thread.join(timeout=2)


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
        self._supplicant: Optional[SupplicantMonitor] = None   # P-43

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
        # P-43: wpa_supplicant reason-code watch (deauth signature)
        self._supplicant = SupplicantMonitor(self.events)
        self._supplicant.start()
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
            "deauth_watch": (self._supplicant.status()
                             if self._supplicant is not None
                             else {"active": False,
                                   "observations_kept": 0,
                                   "incoming_deauth_disconnects": 0}),
            "available": self.available(),
        }

    def stop(self):
        self._stop.set()
        if self._supplicant:
            self._supplicant.stop()
        if self._thread:
            self._thread.join(timeout=2)
