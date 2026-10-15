"""DnsGuard — resolver configuration watch + resolution sanity checks.

Detects:
- resolver set changes (resolv.conf replaced / resolvectl reconfig) —
  often legitimate (VPN, roaming) so severity starts at notice and
  confidence is unverified unless correlated
- resolution failures and abnormally slow resolutions (feeds the
  "why is my internet slow" health verdict)

Pure evaluator + adapter. Uses only the SYSTEM resolver for probes
(socket.getaddrinfo) — never queries a custom server, so the probe
reflects exactly what user applications experience.

Field-tested fix (live report 2026-10-15, problem P-24): the event
'DNS resolver set changed [192.168.100.1, fe80::1] -> [127.0.0.53]
(VPN/roaming or manipulation)' fired on every Wi-Fi reconnect.
127.0.0.53 is the systemd-resolved STUB — a benign, system-managed
layer. The watch loop now resolves the stub back to the effective
upstream servers (resolvectl) and only reports real changes; stub
layer transitions alone produce a single informational event.
"""
import socket
import threading
import time
from typing import Any, Dict, List, Optional

from netfend.models.events import EventStore
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn

RESOLV_CONF = "/etc/resolv.conf"
RESOLVED_STUB = "127.0.0.53"   # systemd-resolved stub (P-24)
_STUB_CACHE_S = 30.0            # resolvectl query cache during flapping


def parse_resolv_conf(content: str) -> List[str]:
    """Extract nameserver lines (pure)."""
    servers = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) == 2:
                servers.append(parts[1])
    return servers


class DnsEvaluator:
    """Pure state: baseline servers + last probe result."""

    def __init__(self, probe_slow_s: float = 3.0):
        self.baseline_servers: List[str] = []
        self.probe_slow_s = probe_slow_s
        self._last_change_emitted: Dict[str, float] = {}

    def evaluate_servers(self, servers: List[str], now: float) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        if not servers:
            return events
        if self.baseline_servers and servers != self.baseline_servers:
            key = ",".join(servers)
            if now - self._last_change_emitted.get(key, float("-inf")) >= 300:
                self._last_change_emitted[key] = now
                events.append({
                    "kind": "dns.config_change",
                    "severity": "notice",
                    "confidence": "unverified",
                    "summary": (f"DNS resolver set changed "
                                f"{self.baseline_servers} -> {servers} "
                                f"(VPN/roaming or manipulation)"),
                    "evidence": {"old": self.baseline_servers, "new": servers}})
        self.baseline_servers = servers
        return events

    def evaluate_probe(self, probe: Dict[str, Any], now: float) -> List[Dict[str, Any]]:
        """probe: {ok: bool, elapsed_s: float, error: str|None}"""
        events: List[Dict[str, Any]] = []
        if not probe.get("ok"):
            key = "probe_fail"
            if now - self._last_change_emitted.get(key, float("-inf")) >= 120:
                self._last_change_emitted[key] = now
                events.append({
                    "kind": "dns.resolution_failure",
                    "severity": "warning",
                    "confidence": "suspected",
                    "summary": (f"DNS resolution failed: {probe.get('error')} "
                                f"(resolver down, manipulation, or no connectivity)"),
                    "evidence": probe})
        elif probe.get("elapsed_s", 0) > self.probe_slow_s:
            key = "probe_slow"
            if now - self._last_change_emitted.get(key, float("-inf")) >= 300:
                self._last_change_emitted[key] = now
                events.append({
                    "kind": "dns.slow_resolution",
                    "severity": "notice",
                    "confidence": "suspected",
                    "summary": (f"DNS resolution took {probe['elapsed_s']:.1f}s "
                                f"(slow resolver or packet loss)"),
                    "evidence": probe})
        return events


class DnsGuard:
    """Adapter: resolv.conf watcher thread + periodic probe thread."""

    def __init__(self, nm, events: EventStore):
        self.nm = nm
        self.events = events
        self.evaluator = DnsEvaluator(probe_slow_s=cfg("dns", "probe_timeout_s", 5))
        self.last_probe: Optional[Dict[str, Any]] = None
        self._stop = threading.Event()
        self._watch_thread: Optional[threading.Thread] = None
        self._probe_thread: Optional[threading.Thread] = None
        self._last_mtime: Optional[float] = None
        self._last_size: Optional[int] = None
        self._stub_cache: Optional[List[str]] = None
        self._stub_cache_at: float = 0.0

    def start(self) -> bool:
        if not cfg("dns", "enabled", True):
            return False
        # Seed baseline from effective resolvers
        servers = self._effective_servers()
        if servers:
            self.evaluator.baseline_servers = servers
        self._watch_thread = threading.Thread(
            target=self._watch_loop, name="nf-dns-watch", daemon=True)
        self._watch_thread.start()
        self._probe_thread = threading.Thread(
            target=self._probe_loop, name="nf-dns-probe", daemon=True)
        self._probe_thread.start()
        log_info("DNS guard active")
        return True

    def _effective_servers(self) -> List[str]:
        # Prefer systemd-resolved when present (it owns resolv.conf stub)
        try:
            import subprocess
            r = subprocess.run(["resolvectl", "--no-pager", "status"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                servers = []
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("DNS Servers"):
                        servers += [s for s in line.split(":", 1)[1].split()
                                    if ":" in s or s.replace(".", "").isdigit()]
                if servers:
                    return servers
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            with open(RESOLV_CONF) as f:
                return parse_resolv_conf(f.read())
        except OSError:
            return []

    def _effective_for_raw(self, raw: List[str]) -> List[str]:
        """P-24: when resolv.conf only points at the systemd-resolved stub,
        resolve the EFFECTIVE upstream servers via resolvectl (cached) so
        stub-layer transitions do not register as resolver changes."""
        if not raw or not all(s == RESOLVED_STUB for s in raw):
            return raw
        now = time.monotonic()
        if (self._stub_cache is not None
                and now - self._stub_cache_at < _STUB_CACHE_S):
            return self._stub_cache
        effective = self._effective_servers()
        # if resolvectl failed, keep the stub itself (still comparable)
        self._stub_cache = effective or raw
        self._stub_cache_at = now
        return self._stub_cache

    def _watch_loop(self):
        interval = cfg("dns", "watch_interval_s", 5)
        while not self._stop.wait(interval):
            try:
                st = self._stat_resolv()
                if st and (st["mtime"] != self._last_mtime or st["size"] != self._last_size):
                    self._last_mtime, self._last_size = st["mtime"], st["size"]
                    self._on_resolv_change()
            except OSError:
                continue

    def _on_resolv_change(self):
        """Handle one resolv.conf change (P-24 stub-aware)."""
        with open(RESOLV_CONF) as f:
            raw = parse_resolv_conf(f.read())
        effective = self._effective_for_raw(raw)
        stub_layer_changed = (
            RESOLVED_STUB in raw
            and self.evaluator.baseline_servers
            and self.evaluator.baseline_servers != raw)
        for ev in self.evaluator.evaluate_servers(effective, time.time()):
            self.events.emit_simple(
                ev["kind"], ev["severity"], ev["confidence"],
                ev["summary"], source="dns", **ev.get("evidence", {}))
        # P-24: pure stub-layer transitions are benign and get a single
        # informational note instead of a warning-flavored 'manipulation'
        # phrasing
        if stub_layer_changed and effective == self.evaluator.baseline_servers:
            self.events.emit_simple(
                "dns.stub_transition", "info", "confirmed",
                "systemd-resolved stub now manages /etc/resolv.conf "
                "(system-managed resolver layer — benign); effective "
                f"upstream servers unchanged: {effective}",
                source="dns", raw=raw, effective=effective)

    def _stat_resolv(self) -> Optional[Dict[str, Any]]:
        try:
            import os
            st = os.stat(RESOLV_CONF)
            return {"mtime": st.st_mtime, "size": st.st_size}
        except OSError:
            return None

    def _probe_loop(self):
        interval = cfg("dns", "probe_interval_s", 60)
        domain = cfg("dns", "probe_domain", "example.com")
        timeout = cfg("dns", "probe_timeout_s", 5)
        while not self._stop.wait(interval):
            probe = self._probe(domain, timeout)
            self.last_probe = probe
            for ev in self.evaluator.evaluate_probe(probe, time.time()):
                self.events.emit_simple(
                    ev["kind"], ev["severity"], ev["confidence"],
                    ev["summary"], source="dns", **ev.get("evidence", {}))

    def _probe(self, domain: str, timeout: float) -> Dict[str, Any]:
        t0 = time.monotonic()
        try:
            socket.setdefaulttimeout(timeout)
            socket.getaddrinfo(domain, None, socket.AF_INET)
            return {"ok": True, "elapsed_s": round(time.monotonic() - t0, 3)}
        except OSError as e:
            return {"ok": False, "elapsed_s": round(time.monotonic() - t0, 3),
                    "error": str(e)}

    def status(self) -> Dict[str, Any]:
        return {
            "resolvers": self.evaluator.baseline_servers,
            "last_probe": self.last_probe,
            "watching": self._watch_thread is not None and self._watch_thread.is_alive(),
        }

    def stop(self):
        self._stop.set()
        for t in (self._watch_thread, self._probe_thread):
            if t:
                t.join(timeout=2)
