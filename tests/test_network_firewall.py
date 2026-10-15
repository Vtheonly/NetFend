"""NetworkManager pure parsers + firewall rulesets + counters."""
import pytest

from netfend.services.network_manager import (
    parse_default_route, parse_ip_addr_json, parse_neigh_output,
    parse_proc_net_dev,
)
from netfend.services.firewall import (
    build_filter_ruleset, build_arp_ruleset, parse_nft_counters,
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
