"""ActiveDefense — bounded corrective self-assertion (ADR-006).

All scapy/kernel interaction is mocked: these tests verify the DECISION
LOGIC (when to act, how much, claiming what identity), not scapy itself.
"""
import time

import pytest

from netfend.services.active_defense import ActiveDefense, _HARD_MAX_PACKETS

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


@pytest.fixture()
def defense(events):
    d = ActiveDefense(FakeNm(), events)
    sent = []

    def fake_send(my_ip, my_mac, count):
        sent.append((my_ip, my_mac, count))
        return count

    d._send_garps = fake_send
    d._sent_log = sent
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


class TestActiveDefense:
    def test_gateway_spoof_triggers_repin_and_self_assertion(self, defense):
        defense.handle_threat(spoof_event())
        _wait_thread()
        assert defense.nm.pins == [(GW["ip"], GW["mac"])]  # kernel re-pin
        assert defense._sent_log == [(MY["ip"], MY["mac"], 5)]  # own identity
        ev = [e for e in defense.events.query(limit=10)
              if e["kind"] == "defense.corrective_action"]
        assert ev, "corrective action must be surfaced as an event"

    def test_only_confirmed_kinds_trigger(self, defense):
        for kind in ("arp.gateway_change", "arp.gateway_oscillation",
                     "dns.config_change", "engine.start"):
            defense.handle_threat({"kind": kind, "evidence": {}})
        _wait_thread()
        assert defense._sent_log == []
        assert defense.nm.pins == []

    def test_own_ip_conflict_triggers_self_assertion_only(self, defense):
        defense.handle_threat({"kind": "arp.own_ip_conflict",
                               "evidence": {"claiming_mac": "de:ad:be:ef:00:02"}})
        _wait_thread()
        assert defense._sent_log, "identity hijack must trigger self-assertion"
        assert defense.nm.pins == []  # no gateway pin for own-IP conflicts

    def test_cooldown_bounds_burst_rate(self, defense):
        for _ in range(10):
            defense.handle_threat(spoof_event())
        _wait_thread()
        assert len(defense._sent_log) == 1  # 60 s cooldown swallowed the rest

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
            else (False if k == "dry_run" else
                  60 if k == "corrective_arp_cooldown_s" else d))
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


def _wait_thread(timeout=2.0):
    """handle_threat spawns a daemon thread; give it a moment."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.02)
