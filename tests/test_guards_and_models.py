"""DHCP, DNS, Wi-Fi, metrics evaluators + threat profile + registries."""
import threading
import time

import pytest

from netfend.services.dhcp_guard import DhcpEvaluator
from netfend.services.dns_guard import DnsEvaluator, parse_resolv_conf
from netfend.services.wifi_diagnostics import (
    classify_wifi_failure, classify_disconnect_pattern, parse_iw_link,
    parse_nmcli_devices,
)
from netfend.services.metrics import compute_rates, health_verdict
from netfend.services.device_registry import DeviceRegistry
from netfend.services.threat_intelligence import ThreatIntelligence


class TestDhcpEvaluator:
    def obs(self, server_ip="192.168.1.1", server_mac="11:11:11:11:11:11",
            msg="offer", router="192.168.1.1", dns=("1.1.1.1",),
            your_ip="192.168.1.77"):
        return {"server_ip": server_ip, "server_mac": server_mac,
                "message_type": msg, "your_ip": your_ip,
                "options": {"router": router, "dns": list(dns)}}

    def test_learning_window(self):
        ev = DhcpEvaluator()
        ev.learn_observations = 2
        now = 1000.0
        assert ev.evaluate(self.obs(), now) == []          # learning 1
        assert ev.evaluate(self.obs(), now + 1) == []      # learning 2
        # a third, different server => rogue
        out = ev.evaluate(self.obs(server_ip="10.66.6.6",
                                   server_mac="de:ad:be:ef:00:66"), now + 2)
        assert any(e["kind"] == "dhcp.rogue_server" for e in out)

    def test_known_server_no_alert(self):
        ev = DhcpEvaluator()
        ev.learn_observations = 2
        now = 1000.0
        ev.evaluate(self.obs(server_ip="192.168.1.1"), now)
        ev.evaluate(self.obs(server_ip="192.168.1.1",
                             server_mac="22:22:22:22:22:22"), now + 1)
        # both became baseline; either may keep talking
        assert ev.evaluate(self.obs(), now + 2) == []

    def test_router_option_change(self):
        ev = DhcpEvaluator()
        ev.learn_observations = 1
        now = 1000.0
        ev.evaluate(self.obs(), now)
        out = ev.evaluate(self.obs(router="10.99.99.99"), now + 10)
        assert any(e["kind"] == "dhcp.router_option_change" for e in out)

    def test_dns_option_change(self):
        ev = DhcpEvaluator()
        ev.learn_observations = 1
        now = 1000.0
        ev.evaluate(self.obs(), now)
        out = ev.evaluate(self.obs(dns=("5.5.5.5",)), now + 10)
        assert any(e["kind"] == "dhcp.dns_option_change" for e in out)

    def test_client_messages_ignored(self):
        ev = DhcpEvaluator()
        ev.learn_observations = 1
        now = 1000.0
        ev.evaluate(self.obs(), now)
        # discover/request from clients say nothing about servers
        assert ev.evaluate(self.obs(msg="request"), now + 1) == []
        assert ev.evaluate(self.obs(msg="discover"), now + 2) == []


class TestDhcpP23:
    """P-23 live-fire regressions: 0.0.0.0 siaddr + mesh infra false flag."""

    def obs(self, server_ip="192.168.100.1", server_mac="1c:73:e2:57:f1:39",
            server_id=None, msg="offer", router="192.168.100.1",
            your_ip="192.168.100.131"):
        return {"server_ip": server_ip, "server_mac": server_mac,
                "message_type": msg, "your_ip": your_ip,
                "options": {"router": router, "dns": ["192.168.100.1"],
                            "server_id": server_id}}

    def test_zero_siaddr_keys_on_mac_not_ip(self):
        """Live case: 'Unexpected DHCP server 0.0.0.0 (1c:73:e2:57:f1:39)'
        — siaddr 0.0.0.0 must never become the server identity."""
        ev = DhcpEvaluator()
        key = ev.server_key(self.obs(server_ip="0.0.0.0", server_id=None))
        assert "0.0.0.0" not in key
        assert "1c:73:e2:57:f1:39" in key

    def test_option54_preferred_over_siaddr(self):
        ev = DhcpEvaluator()
        key = ev.server_key(self.obs(server_ip="0.0.0.0",
                                     server_id="192.168.100.1"))
        assert key.startswith("192.168.100.1|")

    def test_mesh_infra_not_rogue(self):
        """A server identifying as the gateway and offering that gateway as
        router is infrastructure (mesh node), learned with a notice."""
        ev = DhcpEvaluator(gateway={"ip": "192.168.100.1",
                                    "macs": ["1c:73:e2:58:77:17"]})
        ev.learn_observations = 2
        now = 1000.0
        # primary router learned during the learning window
        ev.evaluate(self.obs(server_ip="192.168.100.1",
                             server_mac="1c:73:e2:58:77:17",
                             server_id="192.168.100.1"), now)
        ev.evaluate(self.obs(server_ip="192.168.100.1",
                             server_mac="1c:73:e2:58:77:17",
                             server_id="192.168.100.1"), now + 1)
        # mesh node answers under the same gateway identity => infra, notice
        out = ev.evaluate(self.obs(), now + 2)
        kinds = [e["kind"] for e in out]
        assert "dhcp.infra_server" in kinds
        assert "dhcp.rogue_server" not in kinds
        assert all(e["severity"] != "critical" for e in out)
        # learned: subsequent offers from it are silent
        assert ev.evaluate(self.obs(), now + 3) == []

    def test_real_rogue_still_critical(self):
        """A server NOT matching the gateway identity stays a rogue alert."""
        ev = DhcpEvaluator(gateway={"ip": "192.168.100.1",
                                    "macs": ["1c:73:e2:58:77:17"]})
        ev.learn_observations = 2
        now = 1000.0
        ev.evaluate(self.obs(server_mac="1c:73:e2:58:77:17"), now)
        ev.evaluate(self.obs(server_mac="1c:73:e2:58:77:17"), now + 1)
        out = ev.evaluate(self.obs(server_ip="6.6.6.6",
                                   server_mac="de:ad:be:ef:00:99",
                                   server_id="6.6.6.6",
                                   router="6.6.6.6"), now + 2)
        assert any(e["kind"] == "dhcp.rogue_server"
                   and e["severity"] == "critical" for e in out)

    def test_baseline_persistence_roundtrip(self, tmp_path):
        import json
        ev = DhcpEvaluator()
        ev.learn_observations = 1
        ev.evaluate(self.obs(), 1000.0)
        p = tmp_path / "dhcp_baseline.json"
        p.write_text(json.dumps(ev.to_persist()))
        # a fresh evaluator (engine restart) must not re-learn/re-flag
        ev2 = DhcpEvaluator()
        ev2.load_persisted(json.loads(p.read_text()))
        assert ev2.evaluate(self.obs(), 2000.0) == []


class TestDnsStubAwareness:
    """P-24: systemd-resolved stub (127.0.0.53) is benign system plumbing."""

    def _guard(self, events):
        from netfend.services.dns_guard import DnsGuard

        class FakeNm:
            def snapshot(self):
                return {"interface": "wlan0"}

        return DnsGuard(FakeNm(), events)

    def test_stub_resolved_to_effective_upstreams(self, events):
        g = self._guard(events)
        g.evaluator.baseline_servers = ["192.168.100.1", "fe80::1"]
        # resolv.conf switched to the stub; resolvectl reports the same
        # upstream servers as the baseline
        g._stub_cache = ["192.168.100.1", "fe80::1"]
        g._stub_cache_at = __import__("time").monotonic()
        raw = ["127.0.0.53"]
        effective = g._effective_for_raw(raw)
        assert effective == ["192.168.100.1", "fe80::1"]
        # no resolver-change event: the effective servers did not change
        out = g.evaluator.evaluate_servers(effective, 1000.0)
        assert out == []

    def test_stub_fallback_without_resolvectl(self, events, monkeypatch):
        g = self._guard(events)
        # resolvectl unavailable AND resolv.conf unreadable -> the stub
        # itself is compared (still stable across flaps, no event storm)
        monkeypatch.setattr(g, "_effective_servers", lambda: [])
        effective = g._effective_for_raw(["127.0.0.53"])
        assert effective == ["127.0.0.53"]
        # second call hits the cache, not resolvectl
        assert g._effective_for_raw(["127.0.0.53"]) == ["127.0.0.53"]

    def test_real_resolver_change_still_reported(self, events):
        g = self._guard(events)
        g.evaluator.baseline_servers = ["192.168.100.1"]
        out = g.evaluator.evaluate_servers(["10.0.0.53"], 1000.0)
        assert any(e["kind"] == "dns.config_change" for e in out)

    def test_on_resolv_change_emits_benign_stub_note(self, events, tmp_path,
                                                     monkeypatch):
        """The stub takeover itself gets one informational event with the
        real upstream servers — not a 'manipulation' warning."""
        import netfend.services.dns_guard as dnsmod
        resolv = tmp_path / "resolv.conf"
        monkeypatch.setattr(dnsmod, "RESOLV_CONF", str(resolv))
        g = self._guard(events)
        g.evaluator.baseline_servers = ["192.168.100.1", "fe80::1"]
        # simulate the stub takeover with unchanged effective servers
        resolv.write_text("nameserver 127.0.0.53\n")
        g._stub_cache = ["192.168.100.1", "fe80::1"]
        g._stub_cache_at = __import__("time").monotonic()
        g._on_resolv_change()
        kinds = [e["kind"] for e in events.query(limit=20)]
        assert "dns.stub_transition" in kinds
        assert "dns.config_change" not in kinds


class TestDnsEvaluator:
    def test_parse_resolv_conf(self):
        content = ("# comment\n"
                   "nameserver 192.168.1.1\n"
                   "nameserver 1.1.1.1\n"
                   "options edns0\n")
        assert parse_resolv_conf(content) == ["192.168.1.1", "1.1.1.1"]

    def test_server_change_event(self):
        ev = DnsEvaluator()
        now = 1000.0
        ev.evaluate_servers(["192.168.1.1"], now)
        out = ev.evaluate_servers(["5.5.5.5"], now + 5)
        assert any(e["kind"] == "dns.config_change" for e in out)
        # repeated same set => no repeat event
        assert ev.evaluate_servers(["5.5.5.5"], now + 10) == []

    def test_probe_fail_and_slow(self):
        ev = DnsEvaluator()
        now = 1000.0
        out = ev.evaluate_probe({"ok": False, "elapsed_s": 2.0,
                                 "error": "resolution failed"}, now)
        assert any(e["kind"] == "dns.resolution_failure" for e in out)
        out = ev.evaluate_probe({"ok": True, "elapsed_s": 4.2}, now + 130)
        assert any(e["kind"] == "dns.slow_resolution" for e in out)
        assert ev.evaluate_probe({"ok": True, "elapsed_s": 0.2}, now + 200) == []


class TestWifiClassifier:
    def ctx(self, **kw):
        base = {"assoc_state": "connected", "have_ip": True, "dns_ok": True,
                "rssi": -55, "retries": 0, "weak_rssi": -80}
        base.update(kw)
        return base

    def test_auth_failure(self):
        ev = classify_wifi_failure(self.ctx(assoc_state="associating",
                                            retries=3, have_ip=None))
        assert ev and ev["kind"] == "wifi.auth_failure"

    def test_dhcp_failure(self):
        ev = classify_wifi_failure(self.ctx(have_ip=False))
        assert ev and ev["kind"] == "wifi.dhcp_failure"

    def test_dns_failure(self):
        ev = classify_wifi_failure(self.ctx(dns_ok=False))
        assert ev and ev["kind"] == "wifi.dns_failure"

    def test_weak_signal(self):
        ev = classify_wifi_failure(self.ctx(rssi=-85))
        assert ev and ev["kind"] == "wifi.weak_signal"
        assert ev["confidence"] == "confirmed"

    def test_healthy_none(self):
        assert classify_wifi_failure(self.ctx()) is None
        # few retries not yet failure
        assert classify_wifi_failure(self.ctx(assoc_state="associating",
                                              retries=1)) is None

    def test_disconnect_pattern(self):
        now = 1000.0
        ts = [now - 10, now - 60, now - 120]
        ev = classify_disconnect_pattern(ts, now, count_threshold=3,
                                         window_s=300)
        assert ev and ev["kind"] == "wifi.repeated_disconnects"
        # only 2 in window -> none
        assert classify_disconnect_pattern(ts[:2], now, 3, 300) is None

    def test_parse_iw_link(self):
        out = ("Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n"
               "\tSSID: MyNetwork\n"
               "\tfreq: 2437\n"
               "\tRX: 123456 bytes (1000 packets)\n"
               "\tsignal: -62 dBm\n"
               "\ttx bitrate: 144.4 MBit/s\n")
        info = parse_iw_link(out)
        assert info["connected"] is True
        assert info["ssid"] == "MyNetwork"
        assert info["rssi"] == -62
        assert info["tx_bitrate"] == 144.4
        assert parse_iw_link("Not connected.")["connected"] is False

    def test_parse_nmcli(self):
        out = ("wlan0:802-11-wireless:connected:HomeNet\n"
               "eth0:ethernet:unavailable:\n"
               "lo:loopback:unmanaged:\n")
        d = parse_nmcli_devices(out)
        assert d["wlan0"]["state"] == "connected"
        assert d["wlan0"]["connection"] == "HomeNet"
        assert d["eth0"]["state"] == "unavailable"


class TestDeauthSignature:
    """P-43: forged-deauth flood fingerprint (wpa_supplicant reason codes)."""

    def test_parse_supplicant_disconnect_full(self):
        from netfend.services.wifi_diagnostics import parse_supplicant_disconnect
        line = ("wlo1: CTRL-EVENT-DISCONNECTED bssid=1C:73:E2:57:F1:39 "
                "reason=2 locally_generated=0 freq=2437")
        d = parse_supplicant_disconnect(line)
        assert d == {"bssid": "1c:73:e2:57:f1:39", "reason": 2,
                     "locally_generated": 0}

    def test_parse_supplicant_disconnect_no_locally_generated(self):
        from netfend.services.wifi_diagnostics import parse_supplicant_disconnect
        line = "wlo1: CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=7"
        d = parse_supplicant_disconnect(line)
        assert d["reason"] == 7 and d["locally_generated"] is None

    def test_parse_supplicant_disconnect_non_match(self):
        from netfend.services.wifi_diagnostics import parse_supplicant_disconnect
        assert parse_supplicant_disconnect(
            "wlo1: CTRL-EVENT-BEACON-LOSS freq=2437") is None
        assert parse_supplicant_disconnect(
            "wlo1: CTRL-EVENT-CONNECTED - Connection to xx completed") is None
        assert parse_supplicant_disconnect("garbage") is None

    def test_parse_journal_line(self):
        from netfend.services.wifi_diagnostics import parse_journal_line
        ts, msg = parse_journal_line(
            "1697456789.123456 host wpa_supplicant[991]: wlo1: hi")
        assert abs(ts - 1697456789.123456) < 1e-6 and "wlo1" in msg
        assert parse_journal_line("not a journal line") is None
        assert parse_journal_line("") is None

    def _obs(self, n, reason=2, locally_generated=0, ts_offset=0.0):
        base = 1000.0
        return [{"bssid": "1c:73:e2:57:f1:39", "reason": reason,
                 "locally_generated": locally_generated,
                 "ts": base - i * 5 + ts_offset} for i in range(n)]

    def test_below_threshold_none(self):
        from netfend.services.wifi_diagnostics import classify_deauth_signature
        assert classify_deauth_signature(self._obs(3), now=1000.0,
                                         threshold=4, window_s=180) is None

    def test_flood_fires_critical(self):
        from netfend.services.wifi_diagnostics import classify_deauth_signature
        ev = classify_deauth_signature(self._obs(5), now=1000.0,
                                       threshold=4, window_s=180)
        assert ev and ev["kind"] == "wifi.deauth_signature"
        assert ev["severity"] == "critical"
        assert ev["confidence"] == "suspected"   # honest: PMF would be needed to confirm
        assert "802.11w/PMF" in ev["summary"]
        assert ev["evidence"]["incoming_disconnects"] == 5
        assert ev["evidence"]["reason_counts"] == {"2": 5}

    def test_client_initiated_never_counts(self):
        from netfend.services.wifi_diagnostics import classify_deauth_signature
        # locally_generated=1: the CLIENT sent the deauth (roaming, NM
        # policy, beacon-loss give-up) — never part of the signature
        assert classify_deauth_signature(self._obs(9, locally_generated=1),
                                         now=1000.0, threshold=4,
                                         window_s=180) is None

    def test_non_forged_reasons_never_count(self):
        from netfend.services.wifi_diagnostics import classify_deauth_signature
        # reason 3 = sending STA is leaving (benign); 15/16 = handshake
        # failures (auth problems, different classifier's domain)
        assert classify_deauth_signature(self._obs(9, reason=3),
                                         now=1000.0, threshold=4,
                                         window_s=180) is None

    def test_stale_observations_outside_window(self):
        from netfend.services.wifi_diagnostics import classify_deauth_signature
        assert classify_deauth_signature(self._obs(5, ts_offset=-10000.0),
                                         now=1000.0, threshold=4,
                                         window_s=180) is None

    def test_unknown_locally_generated_excluded(self):
        from netfend.services.wifi_diagnostics import classify_deauth_signature
        obs = [{"bssid": "aa:bb:cc:dd:ee:ff", "reason": 2,
                "locally_generated": None, "ts": 995.0} for _ in range(9)]
        # old supplicants without the field cannot attribute direction —
        # require it rather than guess (false-positive guard)
        assert classify_deauth_signature(obs, now=1000.0, threshold=4,
                                         window_s=180) is None


class TestSupplicantMonitor:
    """P-43 wiring: journal poller, watermark dedup, bounded failure."""

    def _journal_output(self, ts_list, reason=2, locally_generated=0,
                        bssid="1c:73:e2:57:f1:39"):
        lines = []
        for ts in ts_list:
            lines.append(
                f"{ts:.6f} mersel-pc wpa_supplicant[991]: wlo1: "
                f"CTRL-EVENT-DISCONNECTED bssid={bssid} reason={reason} "
                f"locally_generated={locally_generated}")
        return "\n".join(lines)

    def test_poll_ingests_and_fires_event(self, events, monkeypatch):
        import netfend.services.wifi_diagnostics as wmod
        from netfend.services.wifi_diagnostics import SupplicantMonitor

        now = 2000000000.0
        monkeypatch.setattr(wmod, "cfg", lambda s, k, d=None: {
            "supplicant_monitor": True, "supplicant_poll_s": 5,
            "deauth_threshold": 4, "deauth_window_s": 180}.get(k, d))
        fake_time = [now]
        monkeypatch.setattr(wmod.time, "time", lambda: fake_time[0])
        out = self._journal_output([now - 30, now - 25, now - 20, now - 15])
        monkeypatch.setattr(wmod, "_run", lambda cmd: out)

        m = SupplicantMonitor(events)
        m._watermark = now - 60          # pretend engine started a minute ago
        assert m._poll_once() is True
        assert len(m._observations) == 4
        fired = [e for e in events.query(limit=20)
                 if e["kind"] == "wifi.deauth_signature"]
        assert fired and fired[0]["evidence"]["incoming_disconnects"] == 4

    def test_watermark_dedups_overlap(self, events, monkeypatch):
        import netfend.services.wifi_diagnostics as wmod
        from netfend.services.wifi_diagnostics import SupplicantMonitor

        now = 2000000000.0
        monkeypatch.setattr(wmod, "cfg", lambda s, k, d=None: {
            "deauth_threshold": 4, "deauth_window_s": 180}.get(k, d))
        monkeypatch.setattr(wmod.time, "time", lambda: now)
        # the --since overlap re-returns the same lines every poll
        out = self._journal_output([now - 10, now - 5])
        monkeypatch.setattr(wmod, "_run", lambda cmd: out)

        m = SupplicantMonitor(events)
        m._watermark = now - 60
        assert m._poll_once() is True
        assert m._poll_once() is True       # same lines again
        assert len(m._observations) == 2    # no duplicates ingested
        assert m._watermark == pytest.approx(now - 5)

    def test_benign_lines_ingested_without_event(self, events, monkeypatch):
        import netfend.services.wifi_diagnostics as wmod
        from netfend.services.wifi_diagnostics import SupplicantMonitor

        now = 2000000000.0
        monkeypatch.setattr(wmod, "cfg", lambda s, k, d=None: {
            "deauth_threshold": 4, "deauth_window_s": 180}.get(k, d))
        monkeypatch.setattr(wmod.time, "time", lambda: now)
        # client-initiated deauths (roaming) + unrelated lines
        out = (self._journal_output([now - 30, now - 20, now - 10],
                                    reason=3, locally_generated=1)
               + f"\n{now - 5:.6f} host wpa_supplicant[991]: wlo1: "
                 "CTRL-EVENT-BEACON-LOSS freq=2437")
        monkeypatch.setattr(wmod, "_run", lambda cmd: out)

        m = SupplicantMonitor(events)
        m._watermark = now - 60
        assert m._poll_once() is True
        assert len(m._observations) == 3
        assert not [e for e in events.query(limit=20)
                    if e["kind"] == "wifi.deauth_signature"]

    def test_journal_failure_bounded(self, events, monkeypatch):
        import netfend.services.wifi_diagnostics as wmod
        from netfend.services.wifi_diagnostics import (
            SupplicantMonitor, _MAX_CONSECUTIVE_FAILURES)

        monkeypatch.setattr(wmod, "cfg", lambda s, k, d=None: {
            "supplicant_poll_s": 0.01}.get(k, d))
        monkeypatch.setattr(wmod, "_run", lambda cmd: None)  # journalctl dead

        m = SupplicantMonitor(events)
        m._watermark = time.time()
        assert m._poll_once() is False
        # the loop gives up after the bounded failure count
        t = threading.Thread(target=m._loop, daemon=True)
        t.start()
        t.join(timeout=3)
        assert m.active is False
        stopped = [e for e in events.query(limit=20)
                   if e["kind"] == "wifi.supplicant_monitor_stopped"]
        assert stopped

    def test_start_without_journalctl(self, events, monkeypatch):
        import netfend.services.wifi_diagnostics as wmod
        from netfend.services.wifi_diagnostics import SupplicantMonitor

        monkeypatch.setattr(wmod, "cfg", lambda s, k, d=None: {
            "supplicant_monitor": True}.get(k, d))
        monkeypatch.setattr(wmod.capabilities, "have", lambda n: False)
        m = SupplicantMonitor(events)
        assert m.start() is False
        assert not [e for e in events.query(limit=20)
                    if e["kind"] == "wifi.deauth_signature"]
        notices = [e for e in events.query(limit=20)
                   if e["kind"] == "wifi.supplicant_unavailable"]
        assert notices

    def test_status_counts_incoming(self, events, monkeypatch):
        import netfend.services.wifi_diagnostics as wmod
        from netfend.services.wifi_diagnostics import SupplicantMonitor

        now = 2000000000.0
        monkeypatch.setattr(wmod, "cfg", lambda s, k, d=None: {
            "deauth_threshold": 4, "deauth_window_s": 180}.get(k, d))
        monkeypatch.setattr(wmod.time, "time", lambda: now)
        out = self._journal_output([now - 30, now - 25, now - 20, now - 15])
        monkeypatch.setattr(wmod, "_run", lambda cmd: out)
        m = SupplicantMonitor(events)
        m._watermark = now - 60
        m._poll_once()
        st = m.status()
        assert st["active"] is False            # start() not called
        assert st["incoming_deauth_disconnects"] == 4

    def test_poll_boot_bounded_backfill(self, events, monkeypatch):
        """P-44: watermark starts at 0 (backfill the whole boot — the
        engine is After=network-online.target and misses the first
        association attempts), so the journal query MUST be bounded by
        -b (current boot only, never the whole persistent journal)."""
        import netfend.services.wifi_diagnostics as wmod
        from netfend.services.wifi_diagnostics import SupplicantMonitor

        captured = {}

        def fake_run(cmd):
            captured["cmd"] = list(cmd)
            return ""

        monkeypatch.setattr(wmod, "cfg", lambda s, k, d=None: {
            "deauth_threshold": 4, "deauth_window_s": 180}.get(k, d))
        monkeypatch.setattr(wmod, "_run", fake_run)
        m = SupplicantMonitor(events)
        assert m._watermark == 0.0        # set by start(); poll uses it
        m._watermark = 0.0
        m._poll_once()
        assert "-b" in captured["cmd"]
        assert captured["cmd"][
            captured["cmd"].index("--since") + 1].startswith("@0")


class TestMetrics:
    def test_compute_rates(self):
        prev = {"rx_bytes": 1000, "rx_packets": 10, "tx_bytes": 2000,
                "tx_packets": 20}
        cur = {"rx_bytes": 3000, "rx_packets": 30, "tx_bytes": 2500,
               "tx_packets": 25}
        r = compute_rates(prev, cur, 2.0)
        assert r["rx_bps"] == 1000.0
        assert r["tx_bps"] == 250.0
        assert r["rx_pps"] == 10.0
        assert r["tx_pps"] == 2.5

    def test_rates_zero_dt(self):
        prev = cur = {"rx_bytes": 1, "rx_packets": 1, "tx_bytes": 1,
                      "tx_packets": 1}
        r = compute_rates(prev, cur, 0)
        assert r["rx_bps"] == 0.0

    def test_health_verdicts(self):
        v = health_verdict({"loss_pct": 0, "rtt_ms": 12, "dns_ok": True,
                            "gw_ok": True})
        assert v["status"] == "healthy"
        v = health_verdict({"loss_pct": 40, "rtt_ms": 250, "dns_ok": True,
                            "gw_ok": True})
        assert v["status"] == "degraded"
        assert "loss" in v["explanation"].lower()
        v = health_verdict({"loss_pct": 0, "rtt_ms": 10, "dns_ok": False,
                            "gw_ok": True})
        assert "DNS" in v["explanation"]
        v = health_verdict({"loss_pct": 0, "rtt_ms": 10, "dns_ok": True,
                            "gw_ok": False})
        assert v["status"] == "down"


class TestThreatProfile:
    def test_escalation(self, tmp_path):
        from netfend.models.threat_profile import ThreatProfile
        p = ThreatProfile("de:ad:be:ef:00:01")
        escalated = False
        for _ in range(5):
            if p.record_attack("gateway_spoof"):
                escalated = True
        assert escalated
        assert p.threat_level in ("SUSPECT", "HOSTILE")
        assert p.total_attacks == 5

    def test_fingerprint_and_aliases(self, tmp_path):
        intel = ThreatIntelligence(path=tmp_path / "b.json")
        # attacker A with regular timing
        for i in range(8):
            intel.record_attack("de:ad:be:ef:00:01", "gateway_spoof")
        # attacker B (new MAC) with SAME timing signature
        for i in range(8):
            intel.record_attack("de:ad:be:ef:00:02", "gateway_spoof")
        lvl = intel.get_threat_level("de:ad:be:ef:00:02")
        assert lvl is not None
        # fingerprint notes recorded
        s = intel.summary()
        assert any("fingerprint" in n for r in s for n in r["notes"])

    def test_persistence_roundtrip(self, tmp_path):
        p = tmp_path / "b.json"
        intel = ThreatIntelligence(path=p)
        intel.record_attack("de:ad:be:ef:00:01", "identity_spoof")
        intel.save(force=True)
        intel2 = ThreatIntelligence(path=p)
        assert intel2.get_threat_level("de:ad:be:ef:00:01") is not None

    def test_debounced_save(self, tmp_path):
        import time as _t
        p = tmp_path / "b.json"
        intel = ThreatIntelligence(path=p)
        intel._last_save = _t.time()  # pretend we just saved
        intel.record_attack("de:ad:be:ef:00:03", "gateway_spoof")
        assert not p.exists()  # debounced — not written yet
        intel.save(force=True)
        assert p.exists()


class TestThreatAging:
    """P-25: the June profile with 63k attacks must not read CRITICAL
    in October — inactivity decays the effective level."""

    def _aged_profile(self, days, stored_level="CRITICAL"):
        from datetime import datetime, timedelta
        from netfend.models.threat_profile import ThreatProfile
        p = ThreatProfile("d8:3b:bf:2c:a2:b3")
        p.threat_level = stored_level
        p.total_attacks = 63833
        p.last_seen = (datetime.now() - timedelta(days=days)).isoformat()
        return p

    def test_fresh_profile_undecayed(self):
        assert self._aged_profile(1).effective_level() == "CRITICAL"
        assert not self._aged_profile(1).is_stale()

    def test_stale_tiers(self):
        from netfend.models.threat_profile import ThreatProfile
        assert self._aged_profile(20).effective_level() == "HOSTILE"   # 1 level
        assert self._aged_profile(45).effective_level() == "SUSPECT"   # 2 levels
        assert self._aged_profile(100).effective_level() == "MONITOR"  # floor
        assert self._aged_profile(20).is_stale()

    def test_monitor_never_decays_below_floor(self):
        assert self._aged_profile(365, stored_level="MONITOR").effective_level() == "MONITOR"

    def test_summary_sorts_active_before_stale(self, tmp_path):
        from datetime import datetime, timedelta
        intel = ThreatIntelligence(path=tmp_path / "b.json")
        old = intel.record_attack("d8:3b:bf:2c:a2:b3", "gateway_spoof")
        old.total_attacks = 63833
        old.last_seen = (datetime.now() - timedelta(days=110)).isoformat()
        new = intel.record_attack("1c:73:e2:58:77:17", "gateway_spoof")
        new.last_seen = datetime.now().isoformat()
        s = intel.summary()
        assert s[0]["mac"] == "1c:73:e2:58:77:17"   # active first
        assert s[-1]["stale"] is True
        assert s[-1]["effective_threat_level"] == "MONITOR"
        # decision API applies aging too
        assert intel.get_threat_level("d8:3b:bf:2c:a2:b3") == "MONITOR"


class TestDeviceRegistry:
    def test_register_and_authorize(self, tmp_path):
        r = DeviceRegistry(path=tmp_path / "d.json")
        r.register_device("AA:BB:CC:DD:EE:FF", "192.168.1.10")
        assert "aa:bb:cc:dd:ee:ff" in r.get_devices()
        assert not r.is_authorized("aa:bb:cc:dd:ee:ff")
        r.authorize_device("aa:bb:cc:dd:ee:ff", True)
        assert r.is_authorized("aa:bb:cc:dd:ee:ff")

    def test_observation_keeps_authorization(self, tmp_path):
        r = DeviceRegistry(path=tmp_path / "d.json")
        r.register_device("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        r.authorize_device("aa:bb:cc:dd:ee:ff", True)
        # passive observation with default is_authorized=False must NOT
        # revoke the user's authorization
        r.register_device("aa:bb:cc:dd:ee:ff", "192.168.1.99", save=False)
        assert r.is_authorized("aa:bb:cc:dd:ee:ff")

    def test_save_false_no_write(self, tmp_path):
        p = tmp_path / "d.json"
        r = DeviceRegistry(path=p)
        r.register_device("aa:bb:cc:dd:ee:ff", "192.168.1.10", save=False)
        assert not p.exists()
        r.save()
        assert p.exists()

    def test_forget(self, tmp_path):
        r = DeviceRegistry(path=tmp_path / "d.json")
        r.register_device("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        assert r.forget("aa:bb:cc:dd:ee:ff")
        assert "aa:bb:cc:dd:ee:ff" not in r.get_devices()
