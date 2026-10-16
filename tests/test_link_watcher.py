"""P-44 LinkWatcher tests — hermetic: no root, no wireless, no journal.

Coverage:
- iw event line parser across format variants (keyword-keyed, raw kept)
- ip link / iw link extended parsers, band mapping, record formatting
- EvidenceLog: append/query, rotation, cross-process markers, torn lines
- summarize_window counts (feeds the A/B phase classification)
- journal ingest: deauth records + deauth_burst pattern + watermark
  dedup + bounded failure give-up
- state poller: change detection, MAC-change note, gateway flap
- flock single-instance lock
"""
import json
import threading
import time

import pytest

import netfend.services.link_watcher as lw
from netfend.services.link_watcher import (
    EvidenceLog, LinkWatcher, append_marker, acquire_lock,
    band_from_freq, evidence_query, format_record, parse_ip_link_mac,
    parse_iw_event_line, parse_iw_link_ext, summarize_window,
)


# ---------------------------------------------------------------------------
# iw event parser
# ---------------------------------------------------------------------------

class TestIwEventParser:

    def test_auth_line_full_format(self):
        rec = parse_iw_event_line(
            "wlo1: auth 1c:73:e2:57:f1:39 (on 5180 MHz) -> "
            "a0:88:b4:6c:12:34 status: 0")
        assert rec["kind"] == "auth"
        assert rec["iface"] == "wlo1"
        assert rec["freq"] == 5180.0
        assert rec["status"] == 0
        assert rec["bssid_or_peer"] == "1c:73:e2:57:f1:39"
        assert "raw" in rec

    def test_assoc_line(self):
        rec = parse_iw_event_line("wlan0: assoc 00:14:6c:7e:40:80 status: 0")
        assert rec["kind"] == "assoc"
        assert rec["status"] == 0
        assert rec["bssid_or_peer"] == "00:14:6c:7e:40:80"

    def test_assoc_rejected_nonzero_status(self):
        rec = parse_iw_event_line("wlan0: assoc 00:14:6c:7e:40:80 status: 17")
        assert rec["kind"] == "assoc"
        assert rec["status"] == 17

    def test_deauth_line_with_reason(self):
        rec = parse_iw_event_line(
            "wlo1: deauth a0:88:b4:6c:12:34 (on 2412 MHz) "
            "reason 15: 4-way handshake timed out")
        assert rec["kind"] == "deauth"
        assert rec["reason"] == 15
        assert rec["freq"] == 2412.0

    def test_disassoc_line(self):
        rec = parse_iw_event_line(
            "wlan0: disassoc 00:14:6c:7e:40:80 reason 4: inactivity")
        assert rec["kind"] == "disassoc"
        assert rec["reason"] == 4

    def test_phy_suffix_scan_lines(self):
        rec = parse_iw_event_line("wlo1 (phy #0): scan started")
        assert rec["kind"] == "scan"
        assert rec["iface"] == "wlo1"
        rec = parse_iw_event_line(
            "wlo1 (phy #0): scan finished: on freq 2437, entries: 5")
        assert rec["kind"] == "scan"

    def test_two_word_events(self):
        assert parse_iw_event_line(
            "wlan0 (phy #0): new station 00:11:22:33:44:55")["kind"] == "station"
        assert parse_iw_event_line(
            "wlan0 (phy #0): del interface wlan0")["kind"] == "iface_evt"

    def test_unknown_keyword_kept_as_other_with_raw(self):
        line = "wlan0: futuristic-event something entirely new"
        rec = parse_iw_event_line(line)
        assert rec["kind"] == "other"
        assert rec["raw"] == line

    def test_garbage_returns_none(self):
        assert parse_iw_event_line("") is None
        assert parse_iw_event_line("no prefix colon line") is None
        assert parse_iw_event_line("wlan0:") is None  # nothing after colon


# ---------------------------------------------------------------------------
# other pure helpers
# ---------------------------------------------------------------------------

class TestPureHelpers:

    def test_parse_ip_link_mac(self):
        out = ("3: wlo1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...\n"
               "    link/ether A0:88:B4:6C:12:34 brd ff:ff:ff:ff:ff:ff\n")
        assert parse_ip_link_mac(out) == "a0:88:b4:6c:12:34"
        assert parse_ip_link_mac("no mac here") is None

    def test_parse_iw_link_ext(self):
        out = ("Connected to 1c:73:e2:57:f1:39 (on 5180)\n"
               "\tSSID: FAYER\n\tfreq: 5180\n\tsignal: -63.00 dBm\n"
               "\ttx bitrate: 200.0 MBit/s\n")
        info = parse_iw_link_ext(out)
        assert info["connected"] is True
        assert info["ssid"] == "FAYER"
        assert info["rssi"] == -63
        assert info["bssid"] == "1c:73:e2:57:f1:39"
        assert info["freq"] == 5180

    def test_band_from_freq(self):
        assert band_from_freq(2437) == "2.4 GHz"
        assert band_from_freq(5180) == "5 GHz"
        assert band_from_freq(5955) == "6 GHz"
        assert band_from_freq(None) is None
        assert band_from_freq("garbage") is None
        assert band_from_freq(9000) is None

    def test_format_record(self):
        line = format_record({"iso": "2026-10-16T12:00:00+01:00",
                              "kind": "deauth", "reason": 7,
                              "locally_generated": 0, "mac_in_use": "aa:bb:cc:dd:ee:ff",
                              "detail": "CTRL-EVENT-DISCONNECTED ..."})
        assert "2026-10-16T12:00:00" in line
        assert "deauth" in line and "reason=7" in line and "lg=0" in line
        assert "mac=aa:bb:cc:dd:ee:ff" in line

    def test_summarize_window(self):
        records = [
            {"kind": "deauth", "locally_generated": 0, "reason": 7},
            {"kind": "deauth", "locally_generated": 0, "reason": 7},
            {"kind": "deauth", "locally_generated": 1, "reason": 3},
            {"kind": "assoc"},
            {"kind": "assoc_attempt"},
            {"kind": "auth_rejected"},
            {"kind": "state", "associated": True, "gw_mac": "aa:aa:aa:aa:aa:aa"},
            {"kind": "state", "associated": True, "gw_mac": "bb:bb:bb:bb:bb:bb"},
            {"kind": "state", "associated": False},
            {"kind": "deauth_burst"},
            {"kind": "gateway_flap"},
        ]
        s = summarize_window(records)
        assert s["incoming_deauths"] == 2
        assert s["client_deauths"] == 1
        assert s["incoming_reason_counts"] == {"7": 2}
        assert s["assoc_successes"] == 1
        assert s["assoc_attempts"] == 1
        assert s["auth_rejects"] == 1
        assert s["connected_snapshots"] == 2
        assert s["gateway_macs"] == ["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"]
        assert s["deauth_bursts"] == 1
        assert s["gateway_flaps"] == 1


# ---------------------------------------------------------------------------
# EvidenceLog + queries + markers
# ---------------------------------------------------------------------------

class TestEvidenceLog:

    def test_append_and_query(self, tmp_path):
        p = tmp_path / "ev.jsonl"
        log = EvidenceLog(path=p, max_bytes=100000)
        log.append({"kind": "deauth", "reason": 7, "locally_generated": 0})
        log.append({"kind": "state", "associated": True})
        log.close()
        recs = evidence_query(p)
        assert [r["kind"] for r in recs] == ["deauth", "state"]
        assert all("ts" in r and "iso" in r for r in recs)

    def test_rotation_and_query_across_files(self, tmp_path):
        p = tmp_path / "ev.jsonl"
        log = EvidenceLog(path=p, max_bytes=1500)
        for i in range(20):
            log.append({"kind": "state", "i": i,
                        "pad": "x" * 20})
        log.close()
        assert (tmp_path / "ev.jsonl.1").exists()
        recs = evidence_query(p)
        assert len(recs) == 20           # single rotation: nothing lost
        assert recs[0]["i"] == 0 and recs[-1]["i"] == 19
        # a SECOND rotation drops the oldest predecessor (bounded disk)
        log2 = EvidenceLog(path=p, max_bytes=1500)
        for i in range(20, 40):
            log2.append({"kind": "state", "i": i, "pad": "x" * 20})
        log2.close()
        recs = evidence_query(p)
        assert recs[0]["i"] > 0         # oldest records rotated away
        assert recs[-1]["i"] == 39

    def test_append_marker_and_filters(self, tmp_path):
        p = tmp_path / "ev.jsonl"
        append_marker(p, {"kind": "marker", "phase": "real#1", "ts": 100.0})
        append_marker(p, {"kind": "deauth", "ts": 200.0})
        append_marker(p, {"kind": "deauth", "ts": 300.0})
        recs = evidence_query(p, kinds=["deauth"])
        assert len(recs) == 2
        recs = evidence_query(p, since=250.0)
        assert len(recs) == 1 and recs[0]["ts"] == 300.0
        recs = evidence_query(p, until=150.0)
        assert len(recs) == 1 and recs[0]["kind"] == "marker"
        recs = evidence_query(p, limit=2)
        assert len(recs) == 2
        assert recs[-1]["ts"] == 300.0   # limit keeps the NEWEST

    def test_torn_line_skipped(self, tmp_path):
        p = tmp_path / "ev.jsonl"
        p.write_text('{"kind": "deauth", "ts": 1.0}\n'
                     '{"kind": "to' + '  # torn, no newline or invalid json\n'
                     '{"kind": "state", "ts": 2.0}\n')
        recs = evidence_query(p)
        assert [r["kind"] for r in recs] == ["deauth", "state"]


# ---------------------------------------------------------------------------
# watcher journal ingest
# ---------------------------------------------------------------------------

def _journal_lines(ts_list, reason=2, lg=0, bssid="1c:73:e2:57:f1:39"):
    return "\n".join(
        f"{ts:.6f} mersel-pc wpa_supplicant[991]: wlo1: "
        f"CTRL-EVENT-DISCONNECTED bssid={bssid} reason={reason} "
        f"locally_generated={lg}" for ts in ts_list)


class TestWatcherJournal:

    def _watcher(self, tmp_path, fake_run):
        return LinkWatcher(path=tmp_path / "ev.jsonl", run=fake_run)

    def test_journal_ingest_deauth_records(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: True)
        now = 2000000000.0
        out = _journal_lines([now - 40, now - 30])
        w = self._watcher(tmp_path, lambda cmd, timeout=6: out)
        w._journal_poll(now)
        recs = evidence_query(tmp_path / "ev.jsonl", kinds=["deauth"])
        assert len(recs) == 2
        assert recs[0]["reason"] == 2
        assert recs[0]["locally_generated"] == 0
        assert recs[0]["ts"] == pytest.approx(now - 40)  # journal ts, not now

    def test_journal_burst_pattern_fires(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: True)
        now = 2000000000.0
        out = _journal_lines([now - 40, now - 30, now - 20, now - 10])
        w = self._watcher(tmp_path, lambda cmd, timeout=6: out)
        w._journal_poll(now)
        bursts = evidence_query(tmp_path / "ev.jsonl", kinds=["deauth_burst"])
        assert bursts and "forged" in bursts[0]["detail"].lower()

    def test_journal_client_initiated_no_burst(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: True)
        now = 2000000000.0
        out = _journal_lines([now - 40, now - 30, now - 20, now - 10], lg=1)
        w = self._watcher(tmp_path, lambda cmd, timeout=6: out)
        w._journal_poll(now)
        assert not evidence_query(tmp_path / "ev.jsonl", kinds=["deauth_burst"])

    def test_journal_watermark_dedup(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: True)
        now = 2000000000.0
        out = _journal_lines([now - 10, now - 5])
        w = self._watcher(tmp_path, lambda cmd, timeout=6: out)
        w._journal_poll(now)
        w._journal_poll(now)
        assert len(evidence_query(tmp_path / "ev.jsonl")) == 2

    def test_journal_keyword_lines_recorded(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: True)
        now = 2000000000.0
        out = (f"{now - 5:.6f} host wpa_supplicant[991]: wlo1: "
               "Trying to associate with 1c:73:e2:57:f1:39 "
               "(SSID='FAYER' freq=5180 MHz)"
               f"\n{now - 4:.6f} host NetworkManager[777]: <info> "
               "activation of connection 'FAYER' started")
        w = self._watcher(tmp_path, lambda cmd, timeout=6: out)
        w._journal_poll(now)
        recs = evidence_query(tmp_path / "ev.jsonl")
        kinds = [r["kind"] for r in recs]
        assert "assoc_attempt" in kinds and "activation" in kinds

    def test_journal_bounded_failure_gives_up(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: True)
        w = self._watcher(tmp_path, lambda cmd, timeout=6: None)
        for _ in range(5):
            w._journal_poll(2000000000.0)
        assert w._journal_gave_up is True
        # further polls are no-ops; exactly one give-up note, no deauths
        w._journal_poll(2000000000.1)
        recs = evidence_query(tmp_path / "ev.jsonl")
        assert not [r for r in recs if r["kind"] == "deauth"]
        assert sum(1 for r in recs
                   if "no longer recorded" in r.get("detail", "")) == 1


# ---------------------------------------------------------------------------
# watcher state poller
# ---------------------------------------------------------------------------

class FakeStateRunner:
    """Canned outputs for the watcher's state-poll subprocess set."""

    def __init__(self, gw_mac="1c:73:e2:57:f1:39", mac="a0:88:b4:6c:12:34",
                 devices="wlo1:wifi:connected:Home\nlo:loopback:",
                 iw_link=None, ip="192.168.100.90", ping_ok=True,
                 iw_dev="phy#0\n\tInterface wlo1"):
        self.gw_mac = gw_mac
        self.mac = mac
        self.devices = devices
        self.iw_link = iw_link or (
            "Connected to 1c:73:e2:57:f1:39 (on 5180)\n\tSSID: FAYER\n"
            "\tfreq: 5180\n\tsignal: -63.00 dBm\n")
        self.ip = ip
        self.ping_ok = ping_ok
        self.iw_dev = iw_dev

    def __call__(self, cmd, timeout=6):
        c = list(cmd)
        if c[:2] == ["nmcli", "-t"] and "DEVICE,TYPE,STATE" in c:
            return self.devices
        if c[:2] == ["iw", "dev"]:
            if len(c) >= 4 and c[3] == "link":
                return self.iw_link
            return self.iw_dev
        if c[:3] == ["ip", "link", "show"]:
            return (f"3: {c[3]}: <BROADCAST,MULTICAST>\n"
                    f"    link/ether {self.mac} brd ...\n")
        if c[:4] == ["ip", "-4", "addr", "show"]:
            return (f"3: {c[4]}: <BROADCAST>\n    inet {self.ip}/24 "
                    f"brd 192.168.100.255 scope global\n")
        if c[:2] == ["ip", "route"]:
            return "default via 192.168.100.1 dev wlo1 proto dhcp metric 600"
        if c[:2] == ["ip", "neigh"]:
            return (f"192.168.100.1 dev wlo1 lladdr {self.gw_mac} REACHABLE")
        if c[0] == "ping":
            return "1 packets transmitted, 1 received" if self.ping_ok else None
        return None


class TestWatcherStatePoll:

    def test_state_recorded_with_details(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: False)
        w = LinkWatcher(path=tmp_path / "ev.jsonl", run=FakeStateRunner())
        w._state_poll(1000.0)
        states = evidence_query(tmp_path / "ev.jsonl", kinds=["state"])
        assert len(states) == 1
        s = states[0]
        assert s["associated"] is True
        assert s["ssid"] == "FAYER"
        assert s["ip"] == "192.168.100.90"
        assert s["gw_ip"] == "192.168.100.1"
        assert s["gw_mac"] == "1c:73:e2:57:f1:39"
        assert s["gw_ok"] is True
        assert s["band"] == "5 GHz"
        assert s["mac_in_use"] == "a0:88:b4:6c:12:34"

    def test_unchanged_state_heartbeat_only(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: False)
        w = LinkWatcher(path=tmp_path / "ev.jsonl", run=FakeStateRunner())
        w._state_poll(1000.0)
        w._state_poll(1005.0)   # unchanged, within heartbeat
        w._state_poll(1010.0)
        assert len(evidence_query(tmp_path / "ev.jsonl", kinds=["state"])) == 1
        w._state_poll(1100.0)   # past the 60s heartbeat
        assert len(evidence_query(tmp_path / "ev.jsonl", kinds=["state"])) == 2

    def test_mac_change_noted(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: False)
        runner = FakeStateRunner()
        w = LinkWatcher(path=tmp_path / "ev.jsonl", run=runner)
        w._state_poll(1000.0)
        runner.mac = "02:11:22:33:44:55"   # A/B experiment flipped identity
        w._state_poll(1010.0)
        notes = evidence_query(tmp_path / "ev.jsonl", kinds=["note"])
        assert any("MAC is now 02:11:22:33:44:55" in n["detail"] for n in notes)
        states = evidence_query(tmp_path / "ev.jsonl", kinds=["state"])
        assert states[-1]["mac_in_use"] == "02:11:22:33:44:55"

    def test_gateway_flap_detected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: False)
        runner = FakeStateRunner()
        w = LinkWatcher(path=tmp_path / "ev.jsonl", run=runner)
        w._state_poll(1000.0)
        runner.gw_mac = "de:ad:be:ef:00:01"   # ARP poison appears
        w._state_poll(1010.0)
        flaps = evidence_query(tmp_path / "ev.jsonl", kinds=["gateway_flap"])
        assert flaps and "1c:73:e2:57:f1:39" in flaps[0]["gateway_macs"]
        # cooldown: immediate re-detection suppressed
        runner.gw_mac = "1c:73:e2:57:f1:39"
        w._state_poll(1020.0)
        assert len(evidence_query(tmp_path / "ev.jsonl",
                                  kinds=["gateway_flap"])) == 1

    def test_no_wireless_iface_records_note(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: False)
        runner = FakeStateRunner(devices="lo:loopback:unknown:",
                                 iw_dev="phy#0 (no interfaces)")
        w = LinkWatcher(path=tmp_path / "ev.jsonl", run=runner)
        w._state_poll(1000.0)
        notes = evidence_query(tmp_path / "ev.jsonl", kinds=["note"])
        assert any("no wireless interface" in n["detail"] for n in notes)

    def test_disconnected_no_gateway_history(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lw.capabilities, "have", lambda n: False)
        runner = FakeStateRunner(
            iw_link="Not connected.", ip=None, devices="wlo1:wifi:disconnected:")
        w = LinkWatcher(path=tmp_path / "ev.jsonl", run=runner)
        w._state_poll(1000.0)
        assert w._gw_history == []
        states = evidence_query(tmp_path / "ev.jsonl", kinds=["state"])
        assert states[0]["associated"] is False


# ---------------------------------------------------------------------------
# single-instance lock
# ---------------------------------------------------------------------------

class TestAcquireLock:

    def test_second_instance_refused(self, tmp_path):
        lock_path = str(tmp_path / "test.lock")
        fd1, conflict1 = acquire_lock(lock_path)
        assert fd1 is not None and conflict1 is None
        fd2, conflict2 = acquire_lock(lock_path)
        assert fd2 is None
        assert conflict2 is not None
        import os
        os.close(fd1)   # kernel releases on close -> next acquire works
        fd3, conflict3 = acquire_lock(lock_path)
        assert fd3 is not None and conflict3 is None
