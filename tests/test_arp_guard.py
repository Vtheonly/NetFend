"""ARP guard evaluator: attack scenarios + false-positive controls."""
import time

import pytest

from netfend.services.arp_guard import ArpEvaluator

MY = {"ip": "192.168.1.50", "mac": "aa:aa:aa:aa:aa:aa"}
GW = {"ip": "192.168.1.1", "mac": "11:11:11:11:11:11"}
ATTACKER = "de:ad:be:ef:00:01"


def make_evaluator():
    return ArpEvaluator(MY["ip"], MY["mac"], GW["ip"], GW["mac"])


def pkt(op=2, psrc="", hwsrc="", pdst="", hwdst=""):
    return {"op": op, "psrc": psrc, "hwsrc": hwsrc, "pdst": pdst, "hwdst": hwdst}


class TestGatewaySpoof:
    def test_single_observation_no_alert(self):
        """One conflicting frame is not enough (confirmation logic)."""
        ev = make_evaluator()
        now = 1000.0
        out = ev.evaluate(pkt(psrc=GW["ip"], hwsrc=ATTACKER), now)
        assert out == []

    def test_confirmed_conflict_when_old_gw_alive(self):
        """NetCut signature: both MACs claim the gateway simultaneously."""
        ev = make_evaluator()
        now = 1000.0
        # real gateway talks (baseline of liveness)
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=GW["mac"]), now)
        # attacker announces (confirmation 1)
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=ATTACKER), now + 1)
        # attacker again (confirmation 2 -> fires)
        out = ev.evaluate(pkt(psrc=GW["ip"], hwsrc=ATTACKER), now + 2)
        assert any(e["kind"] == "arp.gateway_spoof" for e in out)
        e = next(e for e in out if e["kind"] == "arp.gateway_spoof")
        assert e["severity"] == "critical"
        assert e["confidence"] == "confirmed"

    def test_legitimate_router_replacement_not_an_attack(self):
        """Old gateway silent + new MAC persistent => change, not spoof."""
        ev = make_evaluator()
        now = 1000.0
        new_router = "22:22:22:22:22:22"
        # old gateway seen ONCE long ago (outside 120s liveness window)
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=GW["mac"]), now)
        # new router announces repeatedly much later (old gw stale)
        later = now + 600
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=new_router), later)
        out = ev.evaluate(pkt(psrc=GW["ip"], hwsrc=new_router), later + 1)
        kinds = [e["kind"] for e in out]
        assert "arp.gateway_change" in kinds
        assert "arp.gateway_spoof" not in kinds

    def test_cooldown_prevents_event_storms(self):
        ev = make_evaluator()
        now = 1000.0
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=GW["mac"]), now)
        for i in range(10):
            out = ev.evaluate(pkt(psrc=GW["ip"], hwsrc=ATTACKER), now + i)
        spoof_count = sum(1 for o in out
                          for e in o if e["kind"] == "arp.gateway_spoof")
        assert spoof_count <= 2  # cooldown 60s suppresses repeats


class TestOwnIPConflict:
    def test_foreign_mac_claims_our_ip(self):
        ev = make_evaluator()
        out = ev.evaluate(pkt(psrc=MY["ip"], hwsrc=ATTACKER), 1000.0)
        assert any(e["kind"] == "arp.own_ip_conflict" for e in out)
        e = out[0]
        assert e["severity"] == "warning"

    def test_own_transmissions_ignored(self):
        ev = make_evaluator()
        out = ev.evaluate(pkt(psrc=MY["ip"], hwsrc=MY["mac"]), 1000.0)
        assert out == []


class TestFlapping:
    def test_ip_mac_flapping_detected(self):
        ev = make_evaluator()
        now = 1000.0
        macs = ["de:ad:be:ef:00:01", "de:ad:be:ef:00:02", "de:ad:be:ef:00:03"]
        out = []
        for i, mac in enumerate(macs):
            out = ev.evaluate(pkt(op=1, psrc="192.168.1.99", hwsrc=mac), now + i)
        assert any(e["kind"] == "arp.ip_mac_flapping" for e in out)

    def test_dhcp_reassignment_below_threshold_no_flap(self):
        """2 MACs on one IP (normal DHCP reassignment) must NOT flap."""
        ev = make_evaluator()
        now = 1000.0
        ev.evaluate(pkt(psrc="192.168.1.99", hwsrc="de:ad:be:ef:00:01"), now)
        out = ev.evaluate(pkt(psrc="192.168.1.99", hwsrc="de:ad:be:ef:00:02"),
                          now + 30)
        assert not any(e["kind"] == "arp.ip_mac_flapping" for e in out)


class TestGratuitousFlood:
    def test_flood_detected(self):
        ev = make_evaluator()
        now = 1000.0
        all_events = []
        for i in range(30):
            all_events += ev.evaluate(pkt(psrc="10.0.0.5", hwsrc="de:ad:be:ef:00:09",
                                          pdst="10.0.0.5"), now + i * 0.2)
        assert any(e["kind"] == "arp.gratuitous_flood" for e in all_events)

    def test_normal_garp_rate_not_flagged(self):
        ev = make_evaluator()
        now = 1000.0
        all_events = []
        for i in range(10):
            all_events += ev.evaluate(pkt(psrc="10.0.0.5", hwsrc="de:ad:be:ef:00:09",
                                          pdst="10.0.0.5"), now + i * 1.0)
        assert not any(e["kind"] == "arp.gratuitous_flood" for e in all_events)


class TestMisc:
    def test_malformed_packets_ignored(self):
        ev = make_evaluator()
        assert ev.evaluate({"op": 9, "psrc": "x"}, 1.0) == []
        assert ev.evaluate(pkt(hwsrc="ff:ff:ff:ff:ff:ff"), 1.0) == []
        assert ev.evaluate({"op": None}, 1.0) == []

    def test_rebaseline_clears_state(self):
        ev = make_evaluator()
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=ATTACKER), 1000.0)
        ev.rebaseline("10.0.0.1", "33:33:33:33:33:33")
        assert ev.gw_ip == "10.0.0.1"
        assert len(ev.gw_claims) == 0
        assert len(ev.ip_mac_history) == 0


class TestGatewayRebaseline:
    """P-19 live-fire regression: gateway_change spam + missing feedback."""

    def test_change_event_carries_rebaseline_and_updates_trust(self):
        ev = make_evaluator()
        now = 1000.0
        new_router = "22:22:22:22:22:22"
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=GW["mac"]), now)
        later = now + 600
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=new_router), later)
        out = ev.evaluate(pkt(psrc=GW["ip"], hwsrc=new_router), later + 1)
        change = next(e for e in out if e["kind"] == "arp.gateway_change")
        assert change["rebaseline"]["new_mac"] == new_router
        assert change["evidence"]["rebaselined"] is True
        # trust moved: subsequent frames from the new router are NOT foreign
        assert ev.gw_mac == new_router
        out2 = ev.evaluate(pkt(psrc=GW["ip"], hwsrc=new_router), later + 5)
        assert not any(e["kind"] == "arp.gateway_change" for e in out2)

    def test_no_spam_after_accepted_change(self):
        """The live bug: 106 identical gateway_change events in ~3 min.
        After re-baselining, the same MAC must never re-trigger."""
        ev = make_evaluator()
        now = 1000.0
        new_router = "22:22:22:22:22:22"
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=GW["mac"]), now)
        later = now + 600
        changes = 0
        for i in range(120):  # 2 frames/second for a minute
            out = ev.evaluate(pkt(psrc=GW["ip"], hwsrc=new_router), later + i * 0.5)
            changes += sum(1 for e in out if e["kind"] == "arp.gateway_change")
        assert changes == 1

    def test_oscillation_not_rebaselined(self):
        """Mesh ping-pong: a FORMER trusted MAC returning after silence is
        oscillation, not another router change: trust stays put and ONE
        aggregated event fires instead of a change-flood."""
        ev = make_evaluator()
        now = 1000.0
        other = "22:22:22:22:22:22"
        # seed: trusted gateway seen once
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=GW["mac"]), now)
        # old gw goes silent; other MAC claims gateway (accepted as change)
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=other), now + 200)
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=other), now + 201)
        assert ev.gw_mac == other  # re-baselined to the new MAC
        # ... later the ORIGINAL gateway returns (other silent > 120 s)
        all_events = []
        for i in range(6):
            all_events += ev.evaluate(pkt(psrc=GW["ip"], hwsrc=GW["mac"]),
                                      now + 400 + i)
        osc = [e for e in all_events if e["kind"] == "arp.gateway_oscillation"]
        assert osc, "return of a former gateway MAC must be oscillation"
        assert ev.gw_mac == other          # trust did NOT flip back
        assert len(osc) == 1               # aggregated, not per-packet

    def test_oscillation_event_content(self):
        ev = make_evaluator()
        now = 1000.0
        other = "22:22:22:22:22:22"
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=GW["mac"]), now)
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=other), now + 200)
        ev.evaluate(pkt(psrc=GW["ip"], hwsrc=other), now + 201)
        all_events = []
        for i in range(6):
            all_events += ev.evaluate(pkt(psrc=GW["ip"], hwsrc=GW["mac"]),
                                      now + 400 + i)
        osc = [e for e in all_events if e["kind"] == "arp.gateway_oscillation"]
        e = osc[0]
        assert e["severity"] == "warning"
        assert e["confidence"] == "suspected"
        assert other in e["evidence"]["oscillating_macs"]
        assert GW["mac"] in e["evidence"]["oscillating_macs"]
        assert e["evidence"]["trusted_mac"] == other

    def test_overlapping_claims_stay_conflicts(self):
        """Both MACs actively claiming at the same time is the classic
        poison signature: gateway_spoof (critical/confirmed), NOT a
        legitimate change or oscillation."""
        ev = make_evaluator()
        now = 1000.0
        attacker = "de:ad:be:ef:00:01"
        kinds = []
        for i in range(20):
            mac = GW["mac"] if i % 2 == 0 else attacker
            out = ev.evaluate(pkt(psrc=GW["ip"], hwsrc=mac), now + i)
            kinds += [e["kind"] for e in out]
        assert "arp.gateway_spoof" in kinds
        assert "arp.gateway_change" not in kinds
        assert ev.gw_mac == GW["mac"]   # trust never moved
