"""DHCP, DNS, Wi-Fi, metrics evaluators + threat profile + registries."""
import time

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
