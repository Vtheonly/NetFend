"""ActiveDefense — bounded corrective self-assertion (ADR-006).

All scapy/kernel interaction is mocked: these tests verify the DECISION
LOGIC (when to act, how much, claiming what identity), not scapy itself.

P-28 adds sustained-attack semantics: fresh attack evidence inside the
sustain window switches to a short inter-burst interval (still bounded
by a sliding per-minute packet budget); sporadic attacks keep the long
cooldown; the kernel re-pin is never cooldown-gated.
"""
import time

import pytest

from netfend.services.active_defense import (
    ActiveDefense, _HARD_MAX_PACKETS, _HARD_MAX_PACKETS_PER_MIN,
)

MY = {"ip": "192.168.1.50", "mac": "aa:aa:aa:aa:aa:aa"}
GW = {"ip": "192.168.1.1", "mac": "11:11:11:11:11:11"}


class FakeNm:
    def __init__(self):
        self.pins = []

    def snapshot(self):
        return {"interface": "wlan0", "my_ip": MY["ip"], "my_mac": MY["mac"],
                "gateway_ip": GW["ip"], "gateway_mac": GW["mac"],
                "link_up": True}

    def set_static_neighbor(self, ip, mac):
        self.pins.append((ip, mac))
        return True


class FakeNmNoGw(FakeNm):
    def snapshot(self):
        snap = super().snapshot()
        snap["gateway_mac"] = None
        return snap


@pytest.fixture()
def defense(events):
    d = ActiveDefense(FakeNm(), events)
    sent = []
    unicast = []

    def fake_send(my_ip, my_mac, count):
        sent.append((my_ip, my_mac, count))
        return count

    def fake_unicast(my_ip, my_mac, gw_ip, gw_mac, count):
        unicast.append((my_ip, my_mac, gw_ip, gw_mac, count))
        return count

    d._send_garps = fake_send
    d._send_gateway_unicast = fake_unicast
    d._sent_log = sent
    d._unicast_log = unicast
    # pretend we have root+scapy (gates are tested separately)
    from netfend.utils import capabilities
    capabilities._PROBED = {**capabilities.probe(), "root": True, "scapy": True}
    yield d
    capabilities._PROBED = {}


def spoof_event():
    return {"kind": "arp.gateway_spoof", "severity": "critical",
            "confidence": "confirmed",
            "summary": "Gateway conflict",
            "evidence": {"gateway_ip": GW["ip"],
                         "pinned_gateway_mac": GW["mac"],
                         "conflicting_mac": "de:ad:be:ef:00:01"}}


def oscillation_event():
    return {"kind": "arp.gateway_oscillation", "severity": "warning",
            "confidence": "suspected",
            "summary": "Gateway MAC oscillates",
            "evidence": {"gateway_ip": GW["ip"],
                         "trusted_mac": GW["mac"],
                         "oscillating_macs": ["de:ad:be:ef:00:01",
                                              "de:ad:be:ef:00:02"]}}


class TestActiveDefense:
    def test_gateway_spoof_triggers_repin_and_self_assertion(self, defense):
        defense.handle_threat(spoof_event())
        _wait_thread()
        assert defense.nm.pins == [(GW["ip"], GW["mac"])]  # kernel re-pin
        assert defense._sent_log == [(MY["ip"], MY["mac"], 5)]  # own identity
        assert defense._unicast_log == [
            (MY["ip"], MY["mac"], GW["ip"], GW["mac"], 5)]
        ev = [e for e in defense.events.query(limit=10)
              if e["kind"] == "defense.corrective_action"]
        assert ev, "corrective action must be surfaced as an event"

    def test_only_confirmed_kinds_trigger(self, defense):
        for kind in ("arp.gateway_change", "dns.config_change",
                     "engine.start", "arp.gratuitous_flood"):
            defense.handle_threat({"kind": kind, "evidence": {}})
        _wait_thread()
        assert defense._sent_log == []
        assert defense.nm.pins == []

    def test_oscillation_triggers_repin_and_assertion(self, defense):
        """P-28: a poison/anti-poison fight (oscillation) is an active
        attack — the host must keep its identity asserted."""
        defense.handle_threat(oscillation_event())
        _wait_thread()
        assert defense.nm.pins == [(GW["ip"], GW["mac"])]
        assert defense._sent_log, "oscillation must trigger self-assertion"

    def test_own_ip_conflict_triggers_self_assertion_only(self, defense):
        defense.handle_threat({"kind": "arp.own_ip_conflict",
                               "evidence": {"claiming_mac": "de:ad:be:ef:00:02"}})
        _wait_thread()
        assert defense._sent_log, "identity hijack must trigger self-assertion"
        assert defense.nm.pins == []  # no gateway pin for own-IP conflicts
        # unicast to the gateway is still the NetCut counter-measure
        assert defense._unicast_log

    def test_cooldown_bounds_burst_rate(self, defense):
        for _ in range(10):
            defense.handle_threat(spoof_event())
        _wait_thread()
        # first burst passes; the 10 triggers arrive within milliseconds so
        # even the sustained 5 s minimum interval is not reached
        assert len(defense._sent_log) == 1

    def test_kernel_repin_not_cooldown_gated(self, defense):
        """P-28: re-pinning costs zero packets — it must happen for every
        confirmed spoof even while the packet burst is in cooldown."""
        defense.handle_threat(spoof_event())
        _wait_thread()
        defense.handle_threat(spoof_event())   # within cooldown
        _wait_thread()
        assert len(defense._sent_log) == 1     # packet burst still bounded
        assert len(defense.nm.pins) == 2       # kernel re-pin repeated

    def test_sustained_mode_allows_faster_bursts(self, defense):
        """P-28: continuous re-poisoning (fresh trigger inside the sustain
        window) drops the inter-burst interval from 60 s to 5 s."""
        defense.handle_threat(spoof_event())
        _wait_thread()
        # simulate 6 s of elapsed time with ongoing attack pressure
        defense._last_burst -= 6
        defense._last_trigger -= 6
        defense.handle_threat(spoof_event())  # 6 s after previous trigger
        _wait_thread()
        assert len(defense._sent_log) == 2     # 6 s >= 5 s sustained interval

    def test_sustained_mode_still_respects_short_interval(self, defense):
        """Even under continuous pressure, bursts cannot repeat faster
        than the sustained minimum interval."""
        defense.handle_threat(spoof_event())
        _wait_thread()
        defense._last_burst -= 2               # only 2 s since last burst
        defense._last_trigger -= 2
        defense.handle_threat(spoof_event())
        _wait_thread()
        assert len(defense._sent_log) == 1     # 2 s < 5 s: gated

    def test_sporadic_attack_keeps_long_cooldown(self, defense):
        """A one-off trigger 30 s after the last burst (outside the
        sustain window but inside the normal cooldown) gets no packets."""
        defense.handle_threat(spoof_event())
        _wait_thread()
        defense._last_burst -= 30
        defense._last_trigger -= 30            # 30 s > 12 s window: sporadic
        defense.handle_threat(spoof_event())
        _wait_thread()
        assert len(defense._sent_log) == 1     # 30 s < 60 s cooldown: gated
        assert len(defense.nm.pins) == 2       # re-pin still happens

    def test_budget_caps_packets_per_minute(self, defense):
        """P-28 airtime guard: once the sliding 60 s budget is exhausted,
        bursts are skipped even in sustained mode."""
        # pre-fill the budget window (e.g. from earlier bursts)
        now = time.time()
        defense._burst_history.append((now - 1, 30))   # budget fully used
        defense.handle_threat(spoof_event())
        _wait_thread()
        assert defense._sent_log == []         # no packets this time
        assert defense.budget_skips == 1
        assert defense.nm.pins                 # kernel re-pin still happens
        assert defense.status()["packets_per_minute_ceiling"] == 30

    def test_budget_hard_ceiling_resists_config_typo(self, defense, monkeypatch):
        monkeypatch.setattr(
            "netfend.services.active_defense.cfg",
            lambda s, k, d=None: 100000 if k == "corrective_packets_per_minute"
            else (10000 if k == "corrective_arp_max"
                  else (False if k == "dry_run" else d)))
        assert defense.status()["packets_per_minute_ceiling"] == \
            _HARD_MAX_PACKETS_PER_MIN

    def test_config_gate_off(self, defense):
        from netfend.utils.config import set_config, load_config
        load_config()
        set_config("arp", "corrective_arp_enabled", False)
        defense.handle_threat(spoof_event())
        _wait_thread()
        assert defense._sent_log == []

    def test_hard_ceiling_respected(self, defense, monkeypatch):
        monkeypatch.setattr(
            "netfend.services.active_defense.cfg",
            lambda s, k, d=None: 10000 if k == "corrective_arp_max"
            else (False if k == "dry_run" else d))
        defense.handle_threat(spoof_event())
        _wait_thread()
        assert defense._sent_log[0][2] <= _HARD_MAX_PACKETS

    def test_dry_run_disables(self, defense, monkeypatch):
        monkeypatch.setattr(
            "netfend.services.active_defense.cfg",
            lambda s, k, d=None: True if k == "dry_run" else d)
        defense.handle_threat(spoof_event())
        _wait_thread()
        assert defense._sent_log == []

    def test_no_unicast_without_gateway_mac(self, events):
        d = ActiveDefense(FakeNmNoGw(), events)
        d._send_garps = lambda *a: 0
        unicast = []
        d._send_gateway_unicast = lambda *a: unicast.append(a) or 0
        from netfend.utils import capabilities
        capabilities._PROBED = {**capabilities.probe(), "root": True, "scapy": True}
        try:
            d.handle_threat(spoof_event())
            _wait_thread()
            assert unicast == []   # gateway unknown: broadcast only
        finally:
            capabilities._PROBED = {}


def _wait_thread(timeout=2.0):
    """handle_threat spawns a daemon thread; give it a moment."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.02)
