"""Engine safety invariants + dashboard security + static assets.

These encode the audit's most important guarantees:
- the engine NEVER sends packets in steady state (ADR-002)
- the engine NEVER attacks other devices (ADR-001)
- all threads are daemons; stop() is fast (systemd requirement)
- dashboard: auth matrix, CSRF, no traversal, no secrets
- frontend: required panels present, no external URLs
"""
import ast
import json
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "netfend"


class TestEngineSafetyInvariants:
    """Static analysis guarantees (source-level, per ADR-001/002)."""

    FORBIDDEN_CALLS = {"sendp", "send", "srp", "srp1", "sendpfast"}

    def _scapy_send_calls(self, path: Path):
        tree = ast.parse(path.read_text())
        bad = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.id if isinstance(fn, ast.Name) else (
                    fn.attr if isinstance(fn, ast.Attribute) else None)
                if name in self.FORBIDDEN_CALLS:
                    bad.append((path.name, node.lineno, name))
        return bad

    def test_defense_engine_has_no_packet_sending(self):
        bad = self._scapy_send_calls(PKG / "services" / "defense_engine.py")
        assert bad == [], f"defense_engine.py must not send packets: {bad}"

    def test_arp_guard_sends_nothing(self):
        bad = self._scapy_send_calls(PKG / "services" / "arp_guard.py")
        assert bad == [], f"arp_guard.py must be passive: {bad}"

    def test_dhcp_guard_sends_nothing(self):
        bad = self._scapy_send_calls(PKG / "services" / "dhcp_guard.py")
        assert bad == [], f"dhcp_guard.py must be passive: {bad}"

    def test_active_defense_is_the_only_sender(self):
        """ADR-006: only two modules may transmit at all —
        - active_defense.py: bounded corrective self-assertion
        - network_manager.py: one-shot srp for gateway MAC resolution and
          the explicit on-demand scan (pre-existing, documented in ADR-005)
        Any NEW sender must extend this allowlist consciously."""
        allowed = {"active_defense.py", "network_manager.py"}
        senders = set()
        for f in (PKG / "services").glob("*.py"):
            if self._scapy_send_calls(f):
                senders.add(f.name)
        assert senders <= allowed, \
            f"unexpected packet senders: {sorted(senders - allowed)}"
        assert "active_defense.py" in senders

    def test_active_defense_sends_are_bounded_and_self_claiming(self):
        """AST invariants: every sendp call carries count= (never an
        unbounded blast), and the hard ceiling constant stays small."""
        import ast
        src = (PKG / "services" / "active_defense.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.id if isinstance(fn, ast.Name) else (
                    fn.attr if isinstance(fn, ast.Attribute) else None)
                if name == "sendp":
                    kw = {k.arg for k in node.keywords}
                    assert "count" in kw, "sendp without count= (unbounded)"
        # identity safety: the only ARP construction claims our own address
        # (psrc/hwsrc both bound to my_ip/my_mac — see ADR-001/006)
        assert "psrc=my_ip, hwsrc=my_mac" in src
        # the hard ceiling constant must exist and stay small
        assert "_HARD_MAX_PACKETS = 10" in src

    def test_no_global_arptables_flush(self):
        """The legacy `arptables -F` / `nft flush ruleset` must not exist."""
        for f in PKG.rglob("*.py"):
            src = f.read_text()
            assert "arptables" not in src, f"{f} references legacy arptables"
            assert "flush ruleset" not in src, f"{f} flushes global ruleset"

    def test_no_interface_bouncing(self):
        """RC-7: nothing may down/up interfaces to 'fix' connectivity."""
        for f in list(PKG.rglob("*.py")) + [ROOT / "install.sh",
                                            ROOT / "uninstall.sh",
                                            ROOT / "scripts" / "cleanup.sh"]:
            if f.exists():
                src = f.read_text()
                assert "link set" not in src, f"{f} bounces interfaces"

    def test_engine_threads_are_daemons(self):
        from netfend.services.defense_engine import DefenseEngine
        src = (PKG / "services" / "defense_engine.py").read_text()
        # every Thread( in the engine package must set daemon=True
        for f in PKG.rglob("*.py"):
            tree = ast.parse(f.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                        and node.func.id == "Thread":
                    daemon = [k.value.value for k in node.keywords
                              if k.arg == "daemon"]
                    assert daemon == [True], \
                        f"{f.name}:{node.lineno} Thread without daemon=True"

    def test_stop_is_fast(self):
        from netfend.services.defense_engine import DefenseEngine
        engine = DefenseEngine()
        engine.start()
        time.sleep(0.5)
        t0 = time.monotonic()
        engine.stop()
        assert time.monotonic() - t0 < 5.0

    def test_engine_starts_degraded_without_capabilities(self):
        """This test env lacks root/scapy/nft — engine must still run."""
        from netfend.services.defense_engine import DefenseEngine
        engine = DefenseEngine()
        assert engine.start() is True
        assert engine.running
        assert engine.events.count_since(0) > 0  # capability events emitted
        engine.stop()


class TestDashboardSecurity:
    @pytest.fixture()
    def server(self):
        from netfend.services.defense_engine import DefenseEngine
        from netfend.dashboard.server import DashboardServer
        engine = DefenseEngine()
        engine.start()
        srv = DashboardServer(engine, engine.events, bind="127.0.0.1",
                              port=0)  # ephemeral port
        assert srv.start()
        srv.port = srv._httpd.server_address[1]
        yield srv
        engine.stop()
        srv.stop()

    def _url(self, srv, path):
        return f"http://127.0.0.1:{srv.port}{path}"

    def test_static_served_and_traversal_blocked(self, server):
        import urllib.request, urllib.error
        r = urllib.request.urlopen(self._url(server, "/"), timeout=5)
        assert b"NetFend" in r.read()
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(
                self._url(server, "/../dashboard/auth.py"), timeout=5)
        assert ei.value.code == 404

    def test_api_endpoints_exist(self, server):
        import urllib.request
        for ep in ("overview", "security", "events", "topology",
                   "performance", "attack_protection", "capabilities"):
            r = urllib.request.urlopen(
                self._url(server, f"/api/{ep}"), timeout=5)
            assert r.status == 200
            json.loads(r.read())

    def test_post_requires_token_and_csrf(self, server):
        import urllib.request, urllib.error
        base = self._url(server, "/api/action/reload-config")
        # no token
        with pytest.raises(urllib.error.HTTPError) as e1:
            urllib.request.urlopen(base, data=b"{}", timeout=5)
        assert e1.value.code == 401
        # bad token
        req = urllib.request.Request(base, data=b"{}",
                                     headers={"X-NetFend-Token": "wrong"})
        with pytest.raises(urllib.error.HTTPError) as e2:
            urllib.request.urlopen(req, timeout=5)
        assert e2.value.code == 401
        # good token, no csrf
        tok = server.auth.token_path.read_text().strip()
        req = urllib.request.Request(base, data=b"{}",
                                     headers={"X-NetFend-Token": tok})
        with pytest.raises(urllib.error.HTTPError) as e3:
            urllib.request.urlopen(req, timeout=5)
        assert e3.value.code == 403
        # session + csrf => success
        req = urllib.request.Request(
            self._url(server, "/api/action/session"),
            data=json.dumps({"token": tok}).encode(),
            headers={"X-NetFend-Token": tok})
        csrf = json.loads(urllib.request.urlopen(req, timeout=5).read())["csrf"]
        req = urllib.request.Request(
            base, data=json.dumps({"csrf": csrf}).encode(),
            headers={"X-NetFend-Token": tok})
        r = urllib.request.urlopen(req, timeout=5)
        assert r.status == 200
        # token never echoed anywhere
        assert tok.encode() not in r.read()

    def test_unknown_action_rejected(self, server):
        import urllib.request, urllib.error
        tok = server.auth.token_path.read_text().strip()
        req = urllib.request.Request(
            self._url(server, "/api/action/session"),
            data=json.dumps({"token": tok}).encode(),
            headers={"X-NetFend-Token": tok})
        csrf = json.loads(urllib.request.urlopen(req, timeout=5).read())["csrf"]
        for action, payload in [
                ("shell", {"cmd": "id"}),
                ("exec", {"cmd": "rm -rf /"}),
                ("raw-nft", {"ruleset": "flush ruleset"}),
                ("", {})]:
            req = urllib.request.Request(
                self._url(server, f"/api/action/{action}"),
                data=json.dumps({**payload, "csrf": csrf}).encode(),
                headers={"X-NetFend-Token": tok})
            with pytest.raises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(req, timeout=5)
            assert e.value.code == 404, f"{action} must be unknown"

    def test_login_rate_limited(self, server):
        from netfend.dashboard.auth import DashboardAuth
        auth = DashboardAuth(token_path=server.auth.token_path)
        ip = "10.9.9.9"
        allowed = sum(1 for _ in range(15) if auth.login_rate_ok(ip))
        assert allowed <= 10  # default limit
        assert not auth.login_rate_ok(ip)

    def test_bad_profile_rejected(self, server):
        import urllib.request, urllib.error
        tok = server.auth.token_path.read_text().strip()
        req = urllib.request.Request(
            self._url(server, "/api/action/session"),
            data=json.dumps({"token": tok}).encode(),
            headers={"X-NetFend-Token": tok})
        csrf = json.loads(urllib.request.urlopen(req, timeout=5).read())["csrf"]
        req = urllib.request.Request(
            self._url(server, "/api/action/firewall-profile"),
            data=json.dumps({"csrf": csrf, "profile": "nuke-everything"}).encode(),
            headers={"X-NetFend-Token": tok})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=5)
        assert e.value.code == 400


class TestStaticAssets:
    def test_required_panels_present(self):
        html = (PKG / "dashboard" / "static" / "index.html").read_text()
        for needle in ("Network Overview", "Security Monitoring",
                       "Local Network Attack Protection", "Topology",
                       "Performance"):
            assert needle in html, f"panel missing: {needle}"
        # required data hooks
        for i in ("ov-iface", "ov-ip", "ov-gw", "chart-throughput",
                  "sec-events", "at-arp", "at-dhcp", "at-dns", "at-wifi",
                  "at-defenses", "at-unavailable", "topo", "pf-cpu",
                  "pf-explain", "pf-wifi"):
            assert f'id="{i}"' in html, f"element missing: {i}"

    def test_no_external_urls(self):
        """Offline requirement: no CDN, no external fonts/scripts."""
        for f in (PKG / "dashboard" / "static").iterdir():
            src = f.read_text()
            assert "http://" not in src.replace("http://127.0.0.1", ""), \
                f"{f.name} references external http"
            assert "https://" not in src, f"{f.name} references external https"

    def test_frontend_calls_all_api_endpoints(self):
        import re
        js = (PKG / "dashboard" / "static" / "app.js").read_text()
        called = set(re.findall(r'api\(\s*["\']([a-z_?]+)', js))
        # strip query suffixes used by the events filter call
        called = {c.split("?")[0] for c in called}
        for ep in ("overview", "security", "events", "topology",
                   "performance", "attack_protection"):
            assert ep in called, f"app.js never fetches {ep} (found: {sorted(called)})"
