"""NetworkManager pure parsers + firewall rulesets + counters."""
import pytest

from netfend.services.network_manager import (
    parse_default_route, parse_ip_addr_json, parse_neigh_output,
    parse_proc_net_dev,
)
from netfend.services.firewall import (
    build_filter_ruleset, build_arp_ruleset, parse_nft_counters,
    build_basic_filter_ruleset, build_minimal_filter_ruleset,
    build_minimal_arp_ruleset,
    FILTER_TABLE, ARP_TABLE,
)


class TestParsers:
    def test_default_route_standard(self):
        out = ("default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.50 metric 600\n"
               "192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.50\n")
        r = parse_default_route(out)
        assert r == {"interface": "wlan0", "gateway": "192.168.1.1"}

    def test_default_route_pointopoint_no_via(self):
        out = "default dev ppp0 proto kernel\n"
        r = parse_default_route(out)
        assert r == {"interface": "ppp0", "gateway": None}

    def test_default_route_metric_before_dev(self):
        out = "default via 10.0.0.1 metric 100 dev eth0\n"
        r = parse_default_route(out)
        assert r["interface"] == "eth0" and r["gateway"] == "10.0.0.1"

    def test_no_default(self):
        assert parse_default_route("192.168.1.0/24 dev eth0\n") is None
        assert parse_default_route("") is None

    def test_ip_addr_json_local_key(self):
        # iproute2 uses "local" (discovery persisted in AGENTS.md)
        out = ('[{"ifindex":3,"ifname":"eth0","addr_info":'
               '[{"family":"inet","local":"21.0.9.45","prefixlen":32}]}]')
        assert parse_ip_addr_json(out, "eth0") == "21.0.9.45"

    def test_ip_addr_json_wrong_iface(self):
        out = ('[{"ifname":"wlan0","addr_info":'
               '[{"family":"inet","local":"10.1.2.3"}]}]')
        assert parse_ip_addr_json(out, "eth0") is None

    def test_ip_addr_json_bad(self):
        assert parse_ip_addr_json("not json", "eth0") is None
        assert parse_ip_addr_json('[]', "eth0") is None

    def test_neigh_json(self):
        out = ('[{"dst":"192.168.1.1","lladdr":"aa:bb:cc:dd:ee:ff",'
               '"dev":"wlan0","state":"REACHABLE"}]')
        rows = parse_neigh_output(out)
        assert rows[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert rows[0]["ip"] == "192.168.1.1"

    def test_neigh_text(self):
        out = ("192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
               "192.168.1.2 dev wlan0  FAILED\n")
        rows = parse_neigh_output(out)
        assert len(rows) == 1  # FAILED entry has no lladdr — skipped

    def test_proc_net_dev(self):
        out = (
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
            "  eth0: 1000 10    0    0    0     0          0         0  2000 20       0    0    0     0       0          0\n"
            "  lo: 500 5    0    0    0     0          0         0  500 5    0    0    0     0       0          0\n")
        r = parse_proc_net_dev(out)
        assert r["eth0"]["rx_bytes"] == 1000
        assert r["eth0"]["tx_packets"] == 20
        assert r["lo"]["rx_bytes"] == 500


class TestFirewallRulesets:
    def test_standard_profile(self):
        rs = build_filter_ruleset("standard", 50, 100, 20, 40, [], [53])
        assert f"table inet {FILTER_TABLE}" in rs
        assert "policy accept;" in rs
        assert "meter netfend_synflood" in rs
        assert "ct state invalid drop" in rs
        # strict-only rules absent
        assert "DHCPv4 client" not in rs

    def test_strict_profile(self):
        rs = build_filter_ruleset("strict", 50, 100, 20, 40, [22], [53, 67])
        assert "policy drop;" in rs
        assert 'tcp dport 22 ct state new accept' in rs
        assert "DHCPv4 client" in rs

    def test_invalid_profile_raises(self):
        with pytest.raises(ValueError):
            build_filter_ruleset("yolo", 50, 100, 20, 40, [], [])

    def test_invalid_rates_raise(self):
        with pytest.raises(ValueError):
            build_filter_ruleset("standard", 0, 100, 20, 40, [], [])
        with pytest.raises(ValueError):
            build_filter_ruleset("standard", 50, 100, -1, 40, [], [])

    def test_invalid_ports_raise(self):
        with pytest.raises(ValueError):
            build_filter_ruleset("strict", 50, 100, 20, 40, ["ftp"], [])
        with pytest.raises(ValueError):
            build_filter_ruleset("strict", 50, 100, 20, 40, [], [99999])

    def test_arp_ruleset(self):
        rs = build_arp_ruleset("192.168.1.50", "aa:bb:cc:dd:ee:ff",
                               "192.168.1.1", "11:22:33:44:55:66")
        assert f"table arp {ARP_TABLE}" in rs
        assert "arp saddr mac != aa:bb:cc:dd:ee:ff" in rs
        assert "arp saddr mac != 11:22:33:44:55:66" in rs

    def test_arp_ruleset_no_gateway(self):
        rs = build_arp_ruleset("192.168.1.50", "aa:bb:cc:dd:ee:ff", None, None)
        assert ARP_TABLE in rs
        assert "11:22" not in rs  # no gateway rule

    def test_arp_ruleset_validates_inputs(self):
        with pytest.raises(ValueError):
            build_arp_ruleset("999.1.1.1", "aa:bb:cc:dd:ee:ff", None, None)
        with pytest.raises(ValueError):
            build_arp_ruleset("192.168.1.50", "not-a-mac", None, None)
        with pytest.raises(ValueError):
            build_arp_ruleset("192.168.1.50", "aa:bb:cc:dd:ee:ff",
                              "192.168.1.1", "bogus")

    def test_parse_nft_counters(self):
        sample = """
{"nftables": [{"table": {"family": "arp", "name": "netfend_arp"}},
 {"chain": {"family": "arp", "table": "netfend_arp", "name": "input"}},
 {"rule": {"family": "arp", "table": "netfend_arp", "chain": "input",
   "expr": [{"counter": {"packets": 42, "bytes": 3024}},
            {"comment": "netfend: foreign MAC claims our IP"},
            {"drop": null}]}}]}
"""
        c = parse_nft_counters(sample)
        assert c["netfend: foreign MAC claims our IP"]["packets"] == 42

    def test_parse_nft_counters_garbage(self):
        assert parse_nft_counters("garbage") == {}
        assert parse_nft_counters("[]") == {}


class TestFallbackRulesets:
    """P-18: fallback ladder for nft version incompatibility."""

    def test_basic_filter_no_meters(self):
        rs = build_basic_filter_ruleset("standard", 20, 40)
        assert f"table inet {FILTER_TABLE}" in rs
        assert "meter" not in rs          # the whole point of the fallback
        assert "ct state invalid drop" in rs
        assert "limit rate over 20/second" in rs

    def test_basic_filter_strict_uses_drop_policy(self):
        rs = build_basic_filter_ruleset("strict", 20, 40)
        assert "policy drop;" in rs

    def test_minimal_filter_standard(self):
        rs = build_minimal_filter_ruleset("standard")
        assert "ct state invalid drop" in rs
        assert "limit" not in rs
        assert "policy accept;" in rs

    def test_minimal_filter_strict_keeps_essentials(self):
        rs = build_minimal_filter_ruleset("strict")
        assert "policy drop;" in rs
        assert "DHCPv4 client" in rs        # never cut off DHCP in strict
        assert "icmpv6 essential" in rs     # NDP must survive

    def test_minimal_arp_ruleset(self):
        rs = build_minimal_arp_ruleset("192.168.1.50", "aa:bb:cc:dd:ee:ff")
        assert f"table arp {ARP_TABLE}" in rs
        assert "arp saddr mac != aa:bb:cc:dd:ee:ff" in rs
        assert "gateway IP" not in rs        # own-IP protection only

    def test_strict_full_ruleset_has_no_conflicting_l4_rule(self):
        """The old strict profile contained `meta l4proto tcp ... udp dport 53`
        — a protocol conflict nft rejects. It must stay gone (P-18)."""
        rs = build_filter_ruleset("strict", 50, 100, 20, 40, [22], [53])
        assert "meta l4proto tcp" not in rs
        assert "nonsensical" not in rs


class TestPerTableApply:
    """P-18: the ARP table must never be blocked by filter-table failure."""

    @pytest.fixture()
    def fw(self, events):
        from netfend.services.firewall import FirewallManager

        class FakeNm:
            def snapshot(self):
                return {"interface": "wlan0", "my_ip": "192.168.1.50",
                        "my_mac": "aa:bb:cc:dd:ee:ff",
                        "gateway_ip": "192.168.1.1",
                        "gateway_mac": "11:22:33:44:55:66",
                        "link_up": True}

        return FirewallManager(FakeNm(), events)

    def test_ladder_falls_back_and_reports_first_error(self, fw, monkeypatch):
        calls = []

        def fake_check(ruleset):
            calls.append(ruleset)
            if "meter" in ruleset:      # full variant rejected
                return False, "syntax error: meter not supported"
            return True, None

        monkeypatch.setattr(fw, "_nft_check", fake_check)
        monkeypatch.setattr(fw, "_nft_apply", lambda rs: (True, None))
        ok, err = fw._apply_first_valid([
            ("full", "table inet x { meter y }"),
            ("minimal", "table inet x { }"),
        ], "filter")
        assert ok is True
        assert err == "syntax error: meter not supported"
        assert fw.filter_variant == "minimal"

    def test_ladder_all_rejected(self, fw, monkeypatch):
        monkeypatch.setattr(fw, "_nft_check", lambda rs: (False, "nope"))
        monkeypatch.setattr(fw, "_nft_apply", lambda rs: (True, None))
        ok, err = fw._apply_first_valid([("full", "a"), ("minimal", "b")], "filter")
        assert ok is False
        assert err == "nope"

    def test_arp_applies_even_when_filter_fails(self, fw, events, monkeypatch):
        """Live-fire regression (2026-10-15): filter rejection left the host
        with no ARP protection at all. Now arp wins independently."""
        monkeypatch.setattr(fw, "available", lambda: True)
        monkeypatch.setattr(fw, "_selfcheck", lambda: True)

        def fake_check(ruleset):
            # ARP table (both variants) validates; inet table never does
            if f"table arp {ARP_TABLE}" in ruleset:
                return True, None
            return False, "ip saddr: unsupported in inet table"

        applied_tables = []

        def fake_apply(ruleset):
            applied_tables.append("arp" if f"table arp {ARP_TABLE}" in ruleset
                                  else "inet")
            return True, None

        monkeypatch.setattr(fw, "_nft_check", fake_check)
        monkeypatch.setattr(fw, "_nft_apply", fake_apply)
        assert fw.apply() is True
        assert applied_tables == ["arp"]           # arp applied, inet not
        assert fw.arp_variant in ("full", "minimal")
        assert fw.filter_variant is None
        # validation_failed event must carry the real nft error (P-18)
        val_failed = [e for e in events.query(limit=50)
                      if e["kind"] == "firewall.validation_failed"]
        assert val_failed, "filter failure must be surfaced"
        assert "ip saddr" in val_failed[0]["evidence"].get("nft_error", "")

    def test_apply_reports_fallback_variant(self, fw, events, monkeypatch):
        monkeypatch.setattr(fw, "available", lambda: True)
        monkeypatch.setattr(fw, "_selfcheck", lambda: True)

        def fake_check(ruleset):
            # full filter uses meters -> reject; basic/minimal pass
            if "meter" in ruleset:
                return False, "meter unsupported"
            return True, None

        monkeypatch.setattr(fw, "_nft_check", fake_check)
        monkeypatch.setattr(fw, "_nft_apply", lambda rs: (True, None))
        assert fw.apply() is True
        assert fw.filter_variant == "basic"
        assert fw.arp_variant == "full"
        fallback = [e for e in events.query(limit=50)
                    if e["kind"] == "firewall.fallback"]
        assert fallback and fallback[0]["evidence"].get("variant") == "basic"
