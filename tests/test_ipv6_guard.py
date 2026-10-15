"""Ipv6Guard — mitm6 / rogue-RA suppression and detection (ADR-008, T-32).

Pure decision logic and evaluator run without root/scapy; sysctl
enforcement is exercised against a fake /proc.
"""
import json

import pytest

from netfend.services.ipv6_guard import (
    Ipv6Guard, RaEvaluator, should_enable_ra_guard,
)
from netfend.services.network_manager import parse_default_route
from netfend.services.firewall import (
    build_filter_ruleset, build_basic_filter_ruleset,
)
from netfend.utils import capabilities


V6_ROUTE = ("2001:db8::/64 dev wlan0 proto kernel metric 256\n"
            "default via fe80::1 dev wlan0 proto ra metric 600\n")


class FakeNm:
    def __init__(self, v6_route=True):
        self.v6 = v6_route
        self.interface = "wlan0"

    def snapshot(self):
        return {"interface": "wlan0", "my_ip": "192.168.1.50",
                "my_mac": "aa:aa:aa:aa:aa:aa",
                "gateway_ip": "192.168.1.1", "gateway_mac": None}

    def has_ipv6_default_route(self):
        return self.v6


class TestDecision:
    def test_auto_v4_only_suppresses(self):
        assert should_enable_ra_guard(False, "auto") is True

    def test_auto_v6_in_use_does_not_suppress(self):
        assert should_enable_ra_guard(True, "auto") is False

    def test_auto_unknown_never_suppresses(self):
        """Unknown routing state must fail open for connectivity."""
        assert should_enable_ra_guard(None, "auto") is False

    def test_on_forces(self):
        assert should_enable_ra_guard(True, "on") is True

    def test_off_disables(self):
        assert should_enable_ra_guard(False, "off") is False

    def test_v6_route_parser(self):
        assert parse_default_route(V6_ROUTE) == {
            "interface": "wlan0", "gateway": "fe80::1"}
        assert parse_default_route("2001:db8::/64 dev wlan0\n") is None


class TestRaEvaluator:
    def test_single_source_no_conflict(self):
        ev = RaEvaluator()
        for ts in range(1, 30):
            assert ev.evaluate("fe80::1", float(ts)) == []

    def test_second_source_conflict(self):
        ev = RaEvaluator()
        assert ev.evaluate("fe80::1", 100.0) == []
        events = ev.evaluate("fe80::2", 101.0)   # introduces the conflict
        assert events and events[0]["kind"] == "ipv6.ra_conflict"
        assert events[0]["severity"] == "critical"
        assert sorted(events[0]["evidence"]["sources"]) == \
            ["fe80::1", "fe80::2"]

    def test_conflict_cooldown(self):
        ev = RaEvaluator(cooldown=300)
        ev.evaluate("fe80::1", 100.0)
        assert ev.evaluate("fe80::2", 101.0)   # emits
        assert ev.evaluate("fe80::1", 102.0) == []  # cooldown swallows
        ev.evaluate("fe80::1", 499.0)          # re-anchor inside the window
        assert ev.evaluate("fe80::2", 500.0)   # past cooldown: emits again

    def test_window_prunes_old_sources(self):
        ev = RaEvaluator(window=60)
        ev.evaluate("fe80::1", 100.0)
        # fe80::1 went silent long ago; a NEW lone router is not a conflict
        assert ev.evaluate("fe80::2", 200.0) == []


class TestRulesets:
    ARGS = dict(new_conn_rate=50, new_conn_burst=100, icmp_rate=20,
                icmp_burst=40, strict_tcp_ports=[], strict_udp_ports=[53])

    def test_redirect_drops_always_present(self):
        for ra in (True, False):
            rs = build_filter_ruleset("standard", ra_guard=ra, **self.ARGS)
            assert 'icmp type redirect counter drop' in rs
            assert 'icmpv6 type nd-redirect counter drop' in rs
            basic = build_basic_filter_ruleset("standard", 20, 40, ra_guard=ra)
            assert 'icmp type redirect counter drop' in basic
            assert 'icmpv6 type nd-redirect counter drop' in basic

    def test_ra_drop_only_when_guard_active(self):
        on = build_filter_ruleset("standard", ra_guard=True, **self.ARGS)
        off = build_filter_ruleset("standard", ra_guard=False, **self.ARGS)
        assert "nd-router-advert counter drop" in on
        assert "nd-router-advert" not in off
        basic_on = build_basic_filter_ruleset("standard", 20, 40, ra_guard=True)
        assert "nd-router-advert counter drop" in basic_on

    def test_ra_drop_precedes_strict_icmpv6_accept(self):
        """Even in the strict profile the RA drop must come BEFORE the
        blanket icmpv6 accept, or rogue RAs would be accepted."""
        rs = build_filter_ruleset("strict", ra_guard=True, **self.ARGS)
        assert rs.index("nd-router-advert counter drop") < \
            rs.index("icmpv6 essential")


@pytest.fixture()
def fake_v6_proc(tmp_path):
    base = tmp_path / "proc"
    for rel in ("net/ipv6/conf/all/accept_ra",
                "net/ipv6/conf/default/accept_ra",
                "net/ipv6/conf/wlan0/accept_ra"):
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("1\n")
    return base


@pytest.fixture()
def guard(events, tmp_path, fake_v6_proc, monkeypatch):
    monkeypatch.setattr(capabilities, "have", lambda name: True)
    monkeypatch.setattr("netfend.services.ipv6_guard.DATA_DIR", tmp_path)
    g = Ipv6Guard(FakeNm(v6_route=False), events,
                  proc_base=str(fake_v6_proc))
    return g


class TestEnforcement:
    def read(self, fake_v6_proc, rel):
        return (fake_v6_proc / rel).read_text().strip()

    def test_v4_only_enforces_accept_ra_zero(self, guard, fake_v6_proc,
                                             tmp_path):
        assert guard.evaluate_and_enforce() is True
        assert guard.guard_active is True
        assert self.read(fake_v6_proc, "net/ipv6/conf/all/accept_ra") == "0"
        assert self.read(fake_v6_proc, "net/ipv6/conf/wlan0/accept_ra") == "0"
        state = json.loads((tmp_path / "ipv6_state.json").read_text())
        assert state["net/ipv6/conf/all/accept_ra"] == "1"

    def test_v6_in_use_monitors_only(self, events, tmp_path, fake_v6_proc,
                                     monkeypatch):
        monkeypatch.setattr(capabilities, "have", lambda name: True)
        monkeypatch.setattr("netfend.services.ipv6_guard.DATA_DIR", tmp_path)
        g = Ipv6Guard(FakeNm(v6_route=True), events,
                      proc_base=str(fake_v6_proc))
        assert g.evaluate_and_enforce() is False
        assert self.read(fake_v6_proc, "net/ipv6/conf/all/accept_ra") == "1"

    def test_stop_restores_accept_ra(self, guard, fake_v6_proc):
        guard.evaluate_and_enforce()
        guard.stop()
        assert self.read(fake_v6_proc, "net/ipv6/conf/all/accept_ra") == "1"
        assert self.read(fake_v6_proc, "net/ipv6/conf/wlan0/accept_ra") == "1"

    def test_mode_on_forces_even_with_v6(self, events, tmp_path, fake_v6_proc,
                                         monkeypatch):
        from netfend.utils.config import load_config, set_config
        load_config()
        set_config("ipv6", "ra_guard", "on")
        monkeypatch.setattr(capabilities, "have", lambda name: True)
        monkeypatch.setattr("netfend.services.ipv6_guard.DATA_DIR", tmp_path)
        g = Ipv6Guard(FakeNm(v6_route=True), events,
                      proc_base=str(fake_v6_proc))
        assert g.evaluate_and_enforce() is True

    def test_unknown_route_state_never_suppresses(self, events, tmp_path,
                                                  fake_v6_proc, monkeypatch):
        monkeypatch.setattr(capabilities, "have", lambda name: True)
        monkeypatch.setattr("netfend.services.ipv6_guard.DATA_DIR", tmp_path)

        class UnknownNm(FakeNm):
            def has_ipv6_default_route(self):
                return None

        g = Ipv6Guard(UnknownNm(), events, proc_base=str(fake_v6_proc))
        assert g.evaluate_and_enforce() is False
        assert self.read(fake_v6_proc, "net/ipv6/conf/all/accept_ra") == "1"

    def test_status_shape(self, guard):
        guard.evaluate_and_enforce()
        s = guard.status()
        assert s["guard_active"] is True
        assert "accept_ra=0" in s["suppression"]


class TestEngineWiring:
    def test_engine_passes_ra_guard_to_firewall(self, tmp_path, monkeypatch):
        """The engine must consult Ipv6Guard before building the firewall
        ruleset and forward its decision as ra_guard= (T-32 contract)."""
        from netfend.models.events import EventStore
        from netfend.services.defense_engine import DefenseEngine
        store = EventStore(path=tmp_path / "ev.jsonl")
        try:
            engine = DefenseEngine(events=store)
            captured = {}
            monkeypatch.setattr(
                engine.ipv6_guard, "evaluate_and_enforce",
                lambda: captured.setdefault("decision", True))
            monkeypatch.setattr(
                engine.firewall, "apply",
                lambda **kw: captured.update(kwargs=kw) or True)
            engine._apply_protections()
            assert captured.get("decision") is True
            assert captured.get("kwargs", {}).get("ra_guard") is True
        finally:
            store.close()
