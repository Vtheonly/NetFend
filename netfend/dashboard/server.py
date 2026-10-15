"""Dashboard HTTP server (ADR-004): stdlib-only, localhost, allowlisted API.

Security model:
- binds 127.0.0.1 by default (warning event if configured wider)
- GET /api/* : read-only telemetry. From localhost: allowed without token
  when `dashboard.allow_local_readonly` (default). Remote: token required.
- POST /api/action/<name> : state-changing. ALWAYS requires
  X-NetFend-Token header + valid CSRF token. Allowlist of actions with
  argument validation. No shell execution, no raw firewall strings.
- Static files: fixed allowlist (index.html, style.css, app.js) — no
  directory traversal possible.
- No secrets in responses (token never echoed; resolv.conf servers ARE
  shown — they are not secrets; Wi-Fi passwords never read).
"""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from netfend.dashboard.auth import DashboardAuth
from netfend.models.events import EventStore
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn
from netfend.utils.validators import valid_interface

STATIC_DIR = Path(__file__).parent / "static"
_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}
_LOCALHOST = ("127.0.0.1", "::1")

# POST actions allowlist: name -> (handler, arg spec)
_ACTION_ARGS = {
    "reload-config": [],
    "gateway-rebaseline": [],
    "firewall-profile": ["profile"],
    "wifi-rescan": [],
}
_VALID_PROFILES = ("standard", "strict", "off")


class DashboardServer:
    def __init__(self, engine, events: EventStore,
                 bind: str = None, port: int = None):
        self.engine = engine            # DefenseEngine
        self.events = events
        self.auth = DashboardAuth()
        self.bind = bind or cfg("dashboard", "bind", "127.0.0.1")
        self.port = port or cfg("dashboard", "port", 8787)
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._make_handler()

    # ------------------------------------------------------------------ start
    def start(self) -> bool:
        if not cfg("dashboard", "enabled", True):
            return False
        if self.bind not in _LOCALHOST:
            self.events.emit_simple(
                "dashboard.bind_wide", "warning", "confirmed",
                f"Dashboard bound to {self.bind} — it is NOT localhost-only; "
                f"ensure you trust this network", source="dashboard")
        try:
            self._httpd = ThreadingHTTPServer((self.bind, self.port), self._handler)
            self._httpd.daemon_threads = True
        except OSError as e:
            log_warn(f"Dashboard could not bind {self.bind}:{self.port}: {e}")
            self.events.emit_simple(
                "dashboard.start_failed", "warning", "confirmed",
                f"Dashboard bind failed: {e}", source="dashboard")
            return False
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        name="nf-dashboard", daemon=True)
        self._thread.start()
        log_info(f"Dashboard listening on http://{self.bind}:{self.port}/")
        return True

    def stop(self):
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3)

    # ------------------------------------------------------------------ handler
    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "NetFendDashboard/2.0"

            def log_message(self, fmt, *args):  # silence default stderr spam
                pass

            # ---- helpers ----
            def _client_ip(self) -> str:
                return self.client_address[0]

            def _is_local(self) -> bool:
                return self._client_ip() in _LOCALHOST

            def _send(self, code: int, body: Any,
                      content_type: str = "application/json; charset=utf-8"):
                data = (json.dumps(body) if not isinstance(body, (bytes, str))
                        else body)
                if isinstance(data, str):
                    data = data.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                self.wfile.write(data)

            def _token_ok(self) -> bool:
                presented = self.headers.get("X-NetFend-Token", "")
                return server.auth.check_token(presented)

            # ---- routing ----
            def do_GET(self):
                path = self.path.split("?", 1)[0]
                if path in _STATIC_FILES:
                    return self._serve_static(path)
                if path.startswith("/api/"):
                    return self._serve_api(path)
                self._send(404, {"error": "not found"})

            def _serve_static(self, path: str):
                fname, ctype = _STATIC_FILES[path]
                try:
                    data = (STATIC_DIR / fname).read_bytes()
                except OSError:
                    return self._send(404, {"error": "asset missing"})
                self._send(200, data, ctype)

            def _serve_api(self, path: str):
                # Auth: local readonly allowed without token (default);
                # otherwise token required for ALL api access.
                if not (server.auth.token_is_set()
                        and self._is_local()
                        and cfg("dashboard", "allow_local_readonly", True)):
                    if not self._token_ok():
                        return self._send(401, {"error": "unauthorized"})
                name = path[len("/api/"):]
                import urllib.parse
                params = {k: v[0] for k, v in urllib.parse.parse_qs(
                    urllib.parse.urlparse(self.path).query).items()}
                try:
                    payload = server.api_get(name, params)
                except Exception as e:
                    return self._send(500, {"error": f"internal: {type(e).__name__}"})
                if payload is None:
                    return self._send(404, {"error": "unknown endpoint"})
                self._send(200, payload)

            def do_POST(self):
                path = self.path.split("?", 1)[0]
                if not path.startswith("/api/action/"):
                    return self._send(404, {"error": "not found"})
                # Login endpoint (rate-limited) issues a CSRF session token.
                if path == "/api/action/session":
                    if not server.auth.login_rate_ok(self._client_ip()):
                        return self._send(429, {"error": "rate limited"})
                    length = int(self.headers.get("Content-Length") or 0)
                    if length > 4096:
                        return self._send(413, {"error": "payload too large"})
                    raw = self.rfile.read(length) if length else b""
                    try:
                        body = json.loads(raw or b"{}")
                    except json.JSONDecodeError:
                        return self._send(400, {"error": "bad json"})
                    if not server.auth.check_token(body.get("token", "")):
                        return self._send(401, {"error": "invalid token"})
                    csrf = server.auth.new_session()
                    if csrf is None:
                        return self._send(503, {"error": "session limit"})
                    return self._send(200, {"csrf": csrf, "ttl_s": 3600})

                # State-changing actions: token + CSRF both required.
                if not self._token_ok():
                    return self._send(401, {"error": "unauthorized"})
                length = int(self.headers.get("Content-Length") or 0)
                if length > 4096:
                    return self._send(413, {"error": "payload too large"})
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw or b"{}")
                except json.JSONDecodeError:
                    return self._send(400, {"error": "bad json"})
                if not server.auth.check_csrf(body.get("csrf", "")):
                    return self._send(403, {"error": "bad or missing csrf"})
                action = path[len("/api/action/"):]
                result = server.api_action(action, body)
                self._send(result[0], result[1])

        self._handler = Handler

    # ------------------------------------------------------------------ APIs
    def api_get(self, name: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Read-only telemetry endpoints (allowlisted)."""
        params = params or {}
        if name == "overview":
            return self._api_overview()
        if name == "security":
            return self._api_security()
        if name == "events":
            return self._api_events(params)
        if name == "topology":
            return self._api_topology()
        if name == "performance":
            return self._api_performance()
        if name == "attack_protection":
            return self._api_attack_protection()
        if name == "capabilities":
            from netfend.utils import capabilities
            return capabilities.summary()
        return None

    def _api_overview(self) -> Dict[str, Any]:
        identity = self.engine.nm.snapshot()
        wifi = self.engine.wifi.status()
        verdict = self.engine.metrics.verdict(
            dns_ok=self.engine.dns_guard.last_probe.get("ok")
            if self.engine.dns_guard.last_probe else None,
            weak_signal=(wifi.get("current", {}).get("rssi") is not None
                         and wifi["current"]["rssi"] <= cfg("wifi", "weak_signal_rssi", -80)))
        return {
            "identity": identity,
            "wifi": wifi.get("current", {}),
            "metrics": self.engine.metrics.snapshot(),
            "health": verdict,
            "engine_running": self.engine.running,
            "started_at": self.engine.started_at,
        }

    def _api_security(self) -> Dict[str, Any]:
        return {
            "firewall": self.engine.firewall.status(),
            "threats": self.engine.intel.summary(),
            "counts_24h": {
                "critical": self.events.count_since(
                    __import__("time").time() - 86400, kind_prefix=None),
                "arp": self.events.count_since(
                    __import__("time").time() - 86400, kind_prefix="arp."),
                "dhcp": self.events.count_since(
                    __import__("time").time() - 86400, kind_prefix="dhcp."),
                "dns": self.events.count_since(
                    __import__("time").time() - 86400, kind_prefix="dns."),
                "wifi": self.events.count_since(
                    __import__("time").time() - 86400, kind_prefix="wifi."),
            },
        }

    def _api_events(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Searchable/filterable event log: severity, kind prefix, iface, limit."""
        try:
            limit = min(max(int(params.get("limit", 100)), 1), 500)
        except (TypeError, ValueError):
            limit = 100
        severity = params.get("severity") or None
        kind = params.get("kind") or None
        iface = params.get("iface") or None
        return {"events": self.events.query(
            limit=limit, min_severity=severity,
            kind_prefix=kind, interface=iface)}

    def _api_topology(self) -> Dict[str, Any]:
        """Observed local network. Explicitly labels what is observed vs
        inferred; never fabricates links (owner requirement)."""
        identity = self.engine.nm.snapshot()
        devices = self.engine.registry.get_devices()
        nodes = [{
            "id": "self", "type": "self",
            "label": "This device",
            "ip": identity["my_ip"], "mac": identity["my_mac"],
        }]
        if identity["gateway_ip"]:
            nodes.append({
                "id": "gateway", "type": "gateway",
                "label": "Default gateway",
                "ip": identity["gateway_ip"], "mac": identity["gateway_mac"],
                "observed": bool(identity["gateway_mac"]),
            })
        for mac, info in devices.items():
            if mac == identity["my_mac"]:
                continue
            if identity["gateway_mac"] and mac == identity["gateway_mac"]:
                continue
            nodes.append({
                "id": mac, "type": "host",
                "label": info.get("hostname", "Observed host"),
                "ip": info.get("last_ip"), "mac": mac,
                "authorized": info.get("is_authorized", False),
                "last_seen": info.get("last_seen"),
                "observation": "observed via ARP/neighbor table (no probing)",
            })
        return {
            "nodes": nodes,
            "edges": ([["self", "gateway"]] if identity["gateway_ip"] else []),
            "note": ("Edges show only the default route. Hosts are OBSERVED "
                     "devices; relationships to the gateway are not probed."),
        }

    def _api_performance(self) -> Dict[str, Any]:
        snap = self.engine.metrics.snapshot()
        dns = self.engine.dns_guard.status()
        wifi = self.engine.wifi.status()
        verdict = self.engine.metrics.verdict(
            dns_ok=(dns.get("last_probe") or {}).get("ok"),
            weak_signal=(wifi.get("current", {}).get("rssi") is not None
                         and wifi["current"]["rssi"] <= cfg("wifi", "weak_signal_rssi", -80)))
        return {
            "metrics": snap,
            "dns": dns,
            "wifi": wifi,
            "health": verdict,
        }

    def _api_attack_protection(self) -> Dict[str, Any]:
        """Dedicated Local Network Attack Protection panel (owner req #8)."""
        now = __import__("time").time()
        identity = self.engine.nm.snapshot()
        arp_status = {
            "gateway_pinned": self.engine.firewall.status()["gateway_pinned"],
            "gateway_ip": identity["gateway_ip"],
            "gateway_mac": identity["gateway_mac"],
            "integrity": "ok" if identity["gateway_mac"] else "unresolved",
        }
        recent = self.events.query(limit=200)
        arp_events = [e for e in recent if e["kind"].startswith("arp.")]
        dhcp_events = [e for e in recent if e["kind"].startswith("dhcp.")]
        dns_events = [e for e in recent if e["kind"].startswith("dns.")]
        wifi_events = [e for e in recent if e["kind"].startswith("wifi.")]
        ipv6_events = [e for e in recent if e["kind"].startswith("ipv6.")]
        hardening = self.engine.hardener.status()
        ipv6 = self.engine.ipv6_guard.status()
        dns_status = self.engine.dns_guard.status()
        return {
            "arp": arp_status,
            "arp_events": arp_events[:20],
            "dhcp": {"baseline": self.engine.dhcp_guard.status(),
                     "events": dhcp_events[:10]},
            "dns": {"resolvers": dns_status["resolvers"],
                    "resolvers_lan_only": dns_status.get(
                        "resolvers_lan_only", False),
                    "recommendations": dns_status.get("recommendations", []),
                    "events": dns_events[:10]},
            "ipv6": {"status": ipv6, "events": ipv6_events[:10]},
            "kernel_hardening": hardening,
            "wifi_disruption": {"events": wifi_events[:10],
                                "monitor_mode": self.engine.wifi.status().get(
                                    "monitor_mode_capable", False)},
            "protections_active": {
                "static_gateway_pin": arp_status["gateway_pinned"],
                "nftables_arp_filter": self.engine.firewall.applied,
                "nftables_input_filter": self.engine.firewall.applied,
                "kernel_sysctl_hardening": hardening.get("active", False),
                "ipv6_ra_guard": ipv6.get("guard_active", False),
                "icmp_redirect_drops": self.engine.firewall.applied,
                "arp_inspection": self.engine.arp_guard.available(),
                "dhcp_inspection": self.engine.dhcp_guard.available(),
                "dns_watch": dns_status["watching"],
                "dns_hijack_check": dns_status["watching"],
                "corrective_defense": self.engine.active_defense.status(),
            },
            "unavailable_protections": self._unavailable_protections(),
        }

    def _unavailable_protections(self) -> list:
        from netfend.utils import capabilities
        caps = capabilities.probe()
        out = []
        if not caps.get("nftables"):
            out.append("nftables firewall enforcement (install nftables + root)")
        if not caps.get("scapy"):
            out.append("ARP/DHCP packet inspection (install scapy)")
        if not caps.get("monitor_mode"):
            out.append("frame-level deauth detection (needs monitor mode; "
                       "enable 802.11w/PMF on the router)")
        if not caps.get("root"):
            out.append("all kernel enforcement (run as root/service)")
        return out

    # ------------------------------------------------------------------ actions
    def api_action(self, action: str, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """State-changing POST actions. Allowlisted + validated (ADR-004)."""
        if action not in _ACTION_ARGS:
            return (404, {"error": f"unknown action '{action}'"})
        if action == "reload-config":
            from netfend.utils.config import load_config
            load_config()
            return (200, {"ok": True, "message": "configuration reloaded"})
        if action == "gateway-rebaseline":
            self.engine.nm.refresh()
            self.engine.nm.resolve_mac_background()
            self.engine.arp_guard.rebaseline()
            return (200, {"ok": True,
                          "message": "gateway re-baseline started"})
        if action == "firewall-profile":
            profile = body.get("profile")
            if profile not in _VALID_PROFILES:
                return (400, {"error": f"profile must be one of {_VALID_PROFILES}"})
            from netfend.utils.config import set_config
            set_config("firewall", "profile", profile)
            ok = self.engine.firewall.apply(
                ra_guard=bool(self.engine.ipv6_guard.guard_active))
            msg = f"firewall profile set to {profile}"
            if not ok:
                msg += " (apply deferred — see events)"
            return (200, {"ok": ok, "message": msg})
        if action == "wifi-rescan":
            hosts = self.engine.nm.scan()
            return (200, {"ok": True, "hosts_found": len(hosts)})
        return (400, {"error": "unhandled action"})
