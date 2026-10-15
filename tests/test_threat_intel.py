"""ThreatIntelligence — fuzzy MAC-rotation correlation (P-29).

Dedicated attackers (bettercap, NetCut, custom scripts) rotate MACs
while keeping tool cadence and technique sets. The exact-quantized
fingerprint hash breaks on cadence drift; the fuzzy correlator links
profiles by (tolerant) timing similarity + technique/target overlap,
inherits threat levels across the alias group, persists the links, and
emits intel.mac_rotation events.
"""
from pathlib import Path

import pytest

from netfend.models.threat_profile import ThreatProfile
from netfend.services.threat_intelligence import ThreatIntelligence, jaccard
from netfend.utils.config import THREAT_HOSTILE, THREAT_SUSPECT

GW_IP = "192.168.1.1"


def make_profile(mac, intervals, techniques, spoofed=None, level=None):
    p = ThreatProfile(mac)
    p.burst_intervals = list(intervals)
    p.techniques = set(techniques)
    p.spoofed_ips = set(spoofed or [])
    if level:
        p.threat_level = level
    p.total_attacks = max(10, len(intervals))
    return p


@pytest.fixture()
def intel(tmp_path: Path, events):
    return ThreatIntelligence(path=tmp_path / "bl.json", events=events)


class TestTimingStats:
    def test_mean_stddev_count(self):
        p = make_profile("aa:aa:aa:aa:aa:01", [1.0, 1.1, 0.9, 1.0, 1.0],
                         {"arp.gateway_spoof"})
        s = p.timing_stats()
        assert s["n"] == 5
        assert s["mean"] == pytest.approx(1.0)
        assert 0.05 < s["stddev"] < 0.1

    def test_insufficient_intervals(self):
        assert ThreatProfile("aa:aa:aa:aa:aa:02").timing_stats() is None


class TestLocallyAdministered:
    def test_randomized_bits(self):
        for mac in ("02:00:00:00:00:01", "06:11:22:33:44:55",
                    "0a:aa:aa:aa:aa:aa", "0e:bb:bb:bb:bb:bb"):
            assert ThreatProfile(mac).is_locally_administered()

    def test_vendor_ouis(self):
        for mac in ("00:11:22:33:44:55", "1c:73:e2:58:77:17",
                    "aa:bb:cc:dd:ee:ff"):
            # aa: second nibble 'a' -> 1010, bit 1 set -> locally administered
            if mac[1] == "a":
                continue
            assert not ThreatProfile(mac).is_locally_administered()

    def test_garbage_mac(self):
        assert ThreatProfile("").is_locally_administered() is False


class TestJaccard:
    def test_overlaps(self):
        assert jaccard({"a"}, {"a"}) == 1.0
        assert jaccard({"a"}, {"b"}) == 0.0
        assert jaccard(set(), set()) == 1.0
        assert jaccard({"a", "b"}, {"b", "c"}) == pytest.approx(1 / 3)


class TestMacRotationCorrelation:
    def _seed_known_attacker(self, intel):
        p1 = make_profile("aa:aa:aa:aa:aa:01",
                          [1.0, 1.01, 0.99, 1.0, 1.02, 0.98],
                          {"arp.gateway_spoof"}, [GW_IP], THREAT_HOSTILE)
        intel.profiles[p1.mac] = p1
        return p1

    def test_rotation_correlated_and_level_inherited(self, intel):
        p1 = self._seed_known_attacker(intel)
        # new MAC, same tool cadence (slight drift), same target
        p2 = make_profile("02:de:ad:be:ef:01",
                          [1.04, 1.0, 0.97, 1.03, 1.01, 0.99],
                          {"arp.gateway_spoof"}, [GW_IP])
        intel.profiles[p2.mac] = p2
        found = intel.correlate(p2.mac)
        assert any(f["alias"] == p1.mac for f in found)
        assert p2.threat_level == THREAT_HOSTILE  # inherited
        assert intel.alias_map[p2.mac] == [p1.mac]
        assert intel.alias_map[p1.mac] == [p2.mac]

    def test_rotation_event_emitted_once(self, intel, events):
        self._seed_known_attacker(intel)
        for _ in range(6):
            intel.record_attack("02:de:ad:be:ef:02", "arp.gateway_spoof", GW_IP)
        p2 = intel.profiles["02:de:ad:be:ef:02"]
        p2.burst_intervals = [1.0, 1.02, 0.98, 1.01, 1.0, 0.99]
        p2.spoofed_ips = {GW_IP}
        intel.record_attack("02:de:ad:be:ef:02", "arp.gateway_spoof", GW_IP)
        evs = [e for e in events.query(limit=50)
               if e["kind"] == "intel.mac_rotation"]
        assert evs, "rotation must surface as a dashboard event"
        # and the new profile carries the randomized-MAC note
        assert any("locally-administered" in n for n in p2.notes)

    def test_different_cadence_not_correlated(self, intel):
        self._seed_known_attacker(intel)
        # a slow scanner (30 s cadence) is a different tool
        p2 = make_profile("02:de:ad:be:ef:03",
                          [30.0, 29.0, 31.0, 30.5, 29.5, 30.2],
                          {"arp.gateway_spoof"}, [GW_IP])
        intel.profiles[p2.mac] = p2
        assert intel.correlate(p2.mac) == []
        assert p2.threat_level != THREAT_HOSTILE or p2.mac not in intel.alias_map

    def test_no_overlap_not_correlated(self, intel):
        self._seed_known_attacker(intel)
        # same cadence, but a different technique set AND different target:
        # two different tools that happen to share an interval
        p2 = make_profile("02:de:ad:be:ef:04",
                          [1.0, 1.01, 0.99, 1.0, 1.02, 0.98],
                          {"arp.gratuitous_flood"}, ["192.168.1.77"])
        intel.profiles[p2.mac] = p2
        assert intel.correlate(p2.mac) == []

    def test_same_target_correlates_even_without_technique_overlap(self, intel):
        """Same spoofed gateway IP + same cadence is strong evidence even
        when the recorded technique strings differ (detection paths vary)."""
        self._seed_known_attacker(intel)
        p2 = make_profile("02:de:ad:be:ef:05",
                          [1.0, 1.01, 0.99, 1.0, 1.02, 0.98],
                          {"arp.ip_mac_flapping"}, [GW_IP])
        intel.profiles[p2.mac] = p2
        found = intel.correlate(p2.mac)
        assert any(f["alias"] == "aa:aa:aa:aa:aa:01" for f in found)
        assert found[0]["same_target"] is True

    def test_alias_map_persists(self, intel, tmp_path):
        p1 = self._seed_known_attacker(intel)
        p2 = make_profile("02:de:ad:be:ef:06",
                          [1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
                          {"arp.gateway_spoof"}, [GW_IP])
        intel.profiles[p2.mac] = p2
        intel.correlate(p2.mac)
        intel.save(force=True)
        reloaded = ThreatIntelligence(path=tmp_path / "bl.json")
        assert reloaded.alias_map.get(p2.mac) == [p1.mac]
        assert reloaded.alias_map.get(p1.mac) == [p2.mac]

    def test_no_re_correlation_of_known_alias(self, intel):
        p1 = self._seed_known_attacker(intel)
        p2 = make_profile("02:de:ad:be:ef:07",
                          [1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
                          {"arp.gateway_spoof"}, [GW_IP])
        intel.profiles[p2.mac] = p2
        first = intel.correlate(p2.mac)
        assert first
        second = intel.correlate(p2.mac)  # already linked: no duplicate
        assert second == []

    def test_summary_carries_rotation_fields(self, intel):
        p1 = self._seed_known_attacker(intel)
        p2 = make_profile("02:de:ad:be:ef:08",
                          [1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
                          {"arp.gateway_spoof"}, [GW_IP])
        intel.profiles[p2.mac] = p2
        intel.correlate(p2.mac)
        entries = {e["mac"]: e for e in intel.summary()}
        assert entries[p2.mac]["randomized_mac"] is True
        assert entries[p2.mac]["aliases"] == [p1.mac]
        assert entries[p1.mac]["aliases"] == [p2.mac]

    def test_status_report_flags_randomized(self, intel):
        p = make_profile("02:de:ad:be:ef:09",
                         [1.0] * 6, {"arp.gateway_spoof"}, [GW_IP])
        intel.profiles[p.mac] = p
        lines = intel.get_status_report()
        assert any("RANDOMIZED MAC" in ln for ln in lines)


