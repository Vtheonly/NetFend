"""P-44 IdentityLab tests — hermetic: no NetworkManager, no network.

Coverage:
- random MAC generation (locally-administered bit, determinism)
- nmcli connection-list parsing (escaped colons) + profile selection
- IdentityController: backup snapshot, empty-value normalization,
  auto-heal of leftover backups, apply/restore roundtrip with
  verification, unsupported-property degradation
- phase outcome classification (all five outcomes)
- verdict interpretation matrix (all cells)
- ABTestRunner: full two-phase run with fake clock/probes/nmcli,
  exception-mid-run restore contract, report artifacts
- report rendering
"""
import json
import time

import pytest

import netfend.services.identity_lab as il
from netfend.services.identity_lab import (
    ABTestRunner, IdentityController, ProbeExhausted,
    classify_phase, classify_verdict, parse_nmcli_connections,
    random_local_mac, render_report_md, select_profile,
)


# ---------------------------------------------------------------------------
# MAC generation
# ---------------------------------------------------------------------------

class TestRandomLocalMac:

    def test_locally_administered_unicast_bits(self):
        for _ in range(50):
            m = random_local_mac()
            first = int(m.split(":")[0], 16)
            assert first & 0x02           # locally administered
            assert not (first & 0x01)     # unicast (not multicast)
            assert len(m.split(":")) == 6

    def test_deterministic_with_injected_rng(self):
        assert random_local_mac(
            rng=lambda: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) == "02:11:22:33:44:55"
        # even a multicast-ish first byte gets normalized to unicast-local
        assert random_local_mac(
            rng=lambda: [0xFF, 0x11, 0x22, 0x33, 0x44, 0x55]) == "fe:11:22:33:44:55"

    def test_two_generations_differ(self):
        assert random_local_mac() != random_local_mac()


# ---------------------------------------------------------------------------
# connection list parsing + profile selection
# ---------------------------------------------------------------------------

class TestProfileSelection:

    def test_parse_connections_escaped_colon(self):
        out = ("My\\: Home:802-11-wireless:wlo1:yes\n"
               "Work VPN:vpn::no\n"
               "eth0-profil:802-3-ethernet:eth0:no\n"
               "Cafe:802-11-wireless::no\n")
        rows = parse_nmcli_connections(out)
        assert [r["name"] for r in rows] == ["My: Home", "Cafe"]
        assert rows[0]["active"] is True and rows[1]["active"] is False

    def test_select_active_first(self):
        rows = [{"name": "A", "active": True}, {"name": "B", "active": False}]
        assert select_profile(rows) == ("A", "active")

    def test_select_unique_when_none_active(self):
        rows = [{"name": "Only", "active": False}]
        assert select_profile(rows) == ("Only", "only-wifi-profile")

    def test_select_ambiguous_needs_pin(self):
        rows = [{"name": "A", "active": False}, {"name": "B", "active": False}]
        name, how = select_profile(rows)
        assert name is None and how == "ambiguous-or-none"

    def test_select_by_name_and_ssid(self):
        rows = [{"name": "A", "active": False}, {"name": "B", "active": False}]
        assert select_profile(rows, prefer_name="B") == ("B", "named")
        assert select_profile(rows, prefer_ssid="a") == ("A", "ssid-substring")
        # ambiguous ssid match does not guess
        assert select_profile([{"name": "ax"}, {"name": "ay"}],
                              prefer_ssid="a")[0] is None


# ---------------------------------------------------------------------------
# FakeNM — interprets the nmcli/ip/iw subset the lab uses
# ---------------------------------------------------------------------------

class FakeNM:
    def __init__(self, props=None,
                 connections="Home:802-11-wireless:wlo1:yes",
                 devices="wlo1:wifi:connected:Home",
                 iface_mac="a0:88:b4:6c:12:34",
                 fail_modify_props=(), fail_up=False):
        self.store = dict(props or {})
        self.connections = connections
        self.devices = devices
        self.iface_mac = iface_mac
        self.fail_modify = set(fail_modify_props)
        self.fail_up = fail_up
        self.calls = []

    def __call__(self, cmd, timeout=6):
        c = list(cmd)
        self.calls.append(c)
        if c[0] == "nmcli" and "-g" in c:
            props = c[c.index("-g") + 1].split(",")
            return "\n".join(self.store.get(p, "") for p in props)
        if c[:3] == ["nmcli", "connection", "modify"]:
            prop, value = c[4], c[5]
            if prop in self.fail_modify:
                return None
            self.store[prop] = value
            return ""
        if c[:3] == ["nmcli", "connection", "up"]:
            return None if self.fail_up else "Connection successfully activated"
        if c[:2] == ["nmcli", "device", "disconnect"]:
            return ""
        if c[0] == "nmcli" and "-f" in c:
            fields = c[c.index("-f") + 1]
            if "NAME" in fields:
                return self.connections
            return self.devices
        if c[:3] == ["ip", "link", "show"]:
            return (f"3: {c[3]}: <BROADCAST>\n"
                    f"    link/ether {self.iface_mac} brd ...\n")
        if c[0] == "ping":
            return "1 packets transmitted, 1 received"
        return ""


# ---------------------------------------------------------------------------
# IdentityController
# ---------------------------------------------------------------------------

class TestIdentityController:

    def _ctrl(self, tmp_path, fake_nm):
        return IdentityController("Home", run=fake_nm, data_dir=tmp_path)

    def test_backup_snapshot_defaults_normalized(self, tmp_path):
        nm = FakeNM()      # empty store: everything unset
        ctrl = self._ctrl(tmp_path, nm)
        snap = ctrl.backup()
        assert snap["props"]["wifi.cloned-mac-address"] == "preserve"
        assert snap["props"]["wifi.band"] == "any"
        assert snap["props"]["ipv4.dhcp-send-hostname"] == "yes"
        assert ctrl.backup_file.exists()

    def test_backup_keeps_set_values(self, tmp_path):
        nm = FakeNM(props={"wifi.cloned-mac-address": "permanent",
                           "wifi.band": "a"})
        ctrl = self._ctrl(tmp_path, nm)
        snap = ctrl.backup()
        assert snap["props"]["wifi.cloned-mac-address"] == "permanent"
        assert snap["props"]["wifi.band"] == "a"

    def test_backup_auto_heals_leftover(self, tmp_path):
        nm = FakeNM()
        ctrl = self._ctrl(tmp_path, nm)
        # simulate an interrupted experiment: leftover backup + modified profile
        ctrl.backup_file.parent.mkdir(parents=True, exist_ok=True)
        ctrl.backup_file.write_text(json.dumps(
            {"profile": "Home", "created": 1.0,
             "props": {"wifi.cloned-mac-address": "preserve",
                       "wifi.band": "any",
                       "ipv4.dhcp-send-hostname": "yes",
                       "ipv6.dhcp-send-hostname": "yes"}}))
        nm.store["wifi.cloned-mac-address"] = "de:ad:be:ef:00:01"
        snap = ctrl.backup()   # must restore first, then snapshot
        assert nm.store["wifi.cloned-mac-address"] == "preserve"
        # the OLD backup was consumed; the file now holds the FRESH snapshot
        assert ctrl.backup_file.exists()
        assert snap["created"] > 1.0      # not the leftover one (created=1.0)
        assert snap["props"]["wifi.cloned-mac-address"] == "preserve"

    def test_apply_and_restore_roundtrip(self, tmp_path):
        nm = FakeNM()
        ctrl = self._ctrl(tmp_path, nm)
        ctrl.backup()
        applied = ctrl.apply({"wifi.cloned-mac-address": "02:11:22:33:44:55",
                              "ipv4.dhcp-send-hostname": "no"})
        assert applied["wifi.cloned-mac-address"] == "02:11:22:33:44:55"
        assert nm.store["wifi.cloned-mac-address"] == "02:11:22:33:44:55"
        assert ctrl.restore() is True
        assert nm.store["wifi.cloned-mac-address"] == "preserve"
        assert not ctrl.backup_file.exists()   # deleted only after verified

    def test_restore_without_backup_is_clean(self, tmp_path):
        ctrl = self._ctrl(tmp_path, FakeNM())
        assert ctrl.restore() is True

    def test_unsupported_property_degrades(self, tmp_path):
        nm = FakeNM(fail_modify_props={"ipv6.dhcp-send-hostname"})
        ctrl = self._ctrl(tmp_path, nm)
        ctrl.backup()
        applied = ctrl.apply({"wifi.cloned-mac-address": "02:11:22:33:44:55",
                              "ipv6.dhcp-send-hostname": "no"})
        assert "ipv6.dhcp-send-hostname" not in applied
        assert "wifi.cloned-mac-address" in applied
        # restore must skip the unsupported prop, not fail
        assert ctrl.restore() is True

    def test_current_mac(self, tmp_path):
        ctrl = self._ctrl(tmp_path, FakeNM(iface_mac="02:aa:bb:cc:dd:ee"))
        assert ctrl.current_mac("wlo1") == "02:aa:bb:cc:dd:ee"
        assert ctrl.current_mac("") is None


# ---------------------------------------------------------------------------
# phase classification
# ---------------------------------------------------------------------------

def _poll(assoc=False, ip=None, gw=False, rssi=-63, band="5 GHz"):
    return {"t": 0, "iface": "wlo1",
            "nm_state": "activated" if assoc else "disconnected",
            "associated": assoc, "ssid": "FAYER" if assoc else None,
            "bssid": "1c:73:e2:57:f1:39" if assoc else None,
            "ip": ip, "gw_ip": "192.168.100.1" if gw else None,
            "gw_ok": gw, "rssi": rssi if assoc else None, "band": band}


class TestClassifyPhase:

    def test_rejected(self):
        polls = [_poll() for _ in range(5)]
        r = classify_phase(polls, [])
        assert r["outcome"] == "rejected"

    def test_assoc_no_dhcp(self):
        polls = [_poll(assoc=True) for _ in range(5)]
        r = classify_phase(polls, [])
        assert r["outcome"] == "assoc_no_dhcp"

    def test_connected_no_gw(self):
        polls = [_poll(assoc=True, ip="192.168.100.90") for _ in range(5)]
        r = classify_phase(polls, [])
        assert r["outcome"] == "connected_no_gw"

    def test_connected_lost(self):
        polls = ([_poll(assoc=True, ip="192.168.100.90", gw=True)] * 3
                 + [_poll() for _ in range(3)])
        r = classify_phase(polls, [])
        assert r["outcome"] == "connected_lost"

    def test_connected_unstable_with_deauths(self):
        polls = [_poll(assoc=True, ip="192.168.100.90", gw=True)] * 5
        records = [{"kind": "deauth", "locally_generated": 0, "reason": 7}
                   for _ in range(4)]
        r = classify_phase(polls, records)
        assert r["outcome"] == "connected_unstable"
        assert r["summary"]["incoming_deauths"] == 4

    def test_connected_ok(self):
        polls = [_poll(assoc=True, ip="192.168.100.90", gw=True)] * 5
        r = classify_phase(polls, [])
        assert r["outcome"] == "connected_ok"
        assert r["rssi_min"] == -63

    def test_no_data(self):
        assert classify_phase([], [])["outcome"] == "no_data"


# ---------------------------------------------------------------------------
# verdict matrix
# ---------------------------------------------------------------------------

def _pr(phase, outcome):
    return {"phase": phase, "outcome": outcome, "mac": "x", "cycle": 1,
            "summary": {"incoming_deauths": 0}}


class TestClassifyVerdict:

    def test_identity_targeted(self):
        v = classify_verdict([_pr("real", "rejected"), _pr("random", "connected_ok")])
        assert v["verdict"] == "identity_targeted"
        assert "static target list" in v["explanation"]
        assert v["next_steps"]

    def test_not_identity_only(self):
        v = classify_verdict([_pr("real", "rejected"),
                              _pr("random", "connected_unstable")])
        assert v["verdict"] == "not_identity_only"

    def test_no_active_blocking(self):
        v = classify_verdict([_pr("real", "connected_ok"),
                              _pr("random", "connected_ok")])
        assert v["verdict"] == "no_active_blocking"

    def test_unknown_mac_rejected(self):
        v = classify_verdict([_pr("real", "connected_ok"),
                              _pr("random", "rejected")])
        assert v["verdict"] == "unknown_mac_rejected"

    def test_mixed_inconclusive(self):
        v = classify_verdict([_pr("real", "rejected"),
                              _pr("real", "connected_ok"),
                              _pr("random", "connected_ok")])
        assert v["verdict"] == "inconclusive"

    def test_multiple_cycles_consistent(self):
        v = classify_verdict([_pr("real", "rejected"), _pr("random", "connected_ok"),
                              _pr("real", "connected_lost"),
                              _pr("random", "connected_ok")])
        assert v["verdict"] == "identity_targeted"

    def test_incomplete(self):
        assert classify_verdict([_pr("real", "rejected")])["verdict"] == "incomplete"


# ---------------------------------------------------------------------------
# ABTestRunner — full hermetic run
# ---------------------------------------------------------------------------

class TestABTestRunner:

    def _make_runner(self, tmp_path, polls, fake_nm=None, reconnect=None,
                     t0=1000000.0):
        clock = {"t": t0}
        poll_iter = iter(polls)

        def probe():
            try:
                return next(poll_iter)
            except StopIteration:
                raise ProbeExhausted

        def now():
            return clock["t"]

        def sleep(s):
            clock["t"] += s

        return ABTestRunner(
            profile="Home", cycles=1, dwell_s=30, connect_timeout_s=20,
            probe_s=5, confirm=False, run=fake_nm or FakeNM(),
            path=tmp_path / "ev.jsonl", data_dir=tmp_path,
            now_fn=now, sleep_fn=sleep, probe=probe,
            reconnect_fn=reconnect if reconnect is not None else (lambda: True),
            iface="wlo1"), clock

    def test_full_run_identity_targeted(self, tmp_path, capsys):
        nm = FakeNM()
        polls = ([_poll() for _ in range(12)]                    # real: rejected
                 + [_poll(assoc=True, ip="192.168.100.90", gw=True)
                    for _ in range(12)])                         # random: ok
        runner, _ = self._make_runner(tmp_path, polls, fake_nm=nm)
        rc = runner.run()
        assert rc == 0
        phases = runner.session["phase_results"]
        assert [(p["phase"], p["outcome"]) for p in phases] == [
            ("real", "rejected"), ("random", "connected_ok")]
        # random phase actually applied a locally-administered MAC
        random_mac = phases[1]["mac"]
        assert int(random_mac.split(":")[0], 16) & 0x02
        assert phases[1]["applied"]["wifi.cloned-mac-address"] == random_mac
        assert phases[1]["applied"]["ipv4.dhcp-send-hostname"] == "no"
        # verdict + restore + report artifacts
        assert runner.session["verdict"]["verdict"] == "identity_targeted"
        assert runner.session["restored"] is True
        reports = list((tmp_path / "abtest").glob("*-report.*"))
        assert len(reports) == 2    # .json + .md
        # identity restored in the fake NM
        assert nm.store["wifi.cloned-mac-address"] == "preserve"
        assert nm.store["ipv4.dhcp-send-hostname"] == "yes"
        assert not (tmp_path / "identity-backup.json").exists()
        # markers landed in the evidence log
        import netfend.services.link_watcher as lw
        markers = lw.evidence_query(tmp_path / "ev.jsonl", kinds=["marker"])
        assert any(m["phase"] == "real#1" for m in markers)
        assert any(m["phase"] == "random#1" for m in markers)
        assert any("session started" in m["detail"] for m in markers)
        out = capsys.readouterr().out
        assert "VERDICT: identity_targeted" in out

    def test_exception_mid_run_still_restores(self, tmp_path):
        polls = [_poll() for _ in range(12)]
        nm = FakeNM()

        def explode():
            raise RuntimeError("nmcli exploded")

        runner, _ = self._make_runner(tmp_path, polls, fake_nm=nm,
                                      reconnect=explode)
        with pytest.raises(RuntimeError):
            runner.run()
        # the restore contract held: backup re-applied and removed
        assert nm.store["wifi.cloned-mac-address"] == "preserve"
        assert not (tmp_path / "identity-backup.json").exists()

    def test_dry_run_only_prints_plan(self, tmp_path, capsys, monkeypatch):
        import netfend.utils.config as config_mod
        monkeypatch.setitem(config_mod.DEFAULTS["general"], "dry_run", True)
        polls = []
        runner, _ = self._make_runner(tmp_path, polls)
        rc = runner.run()
        assert rc == 0
        out = capsys.readouterr().out
        assert "dry-run" in out
        # nothing changed anywhere
        assert not (tmp_path / "identity-backup.json").exists()
        assert not list(tmp_path.glob("ev.jsonl*"))

    def test_no_profile_error_guidance(self, tmp_path, capsys):
        nm = FakeNM(connections="A:802-11-wireless::no\nB:802-11-wireless::no")
        runner, _ = self._make_runner(tmp_path, [], fake_nm=nm)
        rc = runner.run()
        assert rc == 1
        out = capsys.readouterr().out
        assert "--profile" in out

    def test_phase_reads_evidence_window(self, tmp_path):
        # seed deauth records INSIDE the experiment window (fake clock)
        t0 = 1000000.0
        ev = tmp_path / "ev.jsonl"
        deauths = "\n".join(json.dumps(
            {"kind": "deauth", "ts": t0 + 25, "locally_generated": 0,
             "reason": 7, "bssid": "1c:73:e2:57:f1:39"}) for _ in range(4))
        ev.write_text(deauths + "\n")
        polls = [_poll(assoc=True, ip="192.168.100.90", gw=True)
                 for _ in range(24)]
        runner, _ = self._make_runner(tmp_path, polls, t0=t0)
        rc = runner.run()
        assert rc == 0
        phases = runner.session["phase_results"]
        # both phases connected; first phase (real) overlapped the deauths
        outcomes = {p["phase"]: p["outcome"] for p in phases}
        assert outcomes["real"] == "connected_unstable"
        assert outcomes["random"] == "connected_ok"
        v = classify_verdict(phases)
        assert v["verdict"] == "identity_targeted"

    def test_band_applied_to_both_phases(self, tmp_path):
        polls = ([_poll(assoc=True, ip="192.168.100.90", gw=True)] * 12
                 + [_poll(assoc=True, ip="192.168.100.90", gw=True,
                          band="5 GHz")] * 12)
        clock_holder = {}

        def _mk():
            pass

        runner, _ = self._make_runner(tmp_path, polls)
        runner.band = "a"
        rc = runner.run()
        assert rc == 0
        for p in runner.session["phase_results"]:
            assert p["applied"].get("wifi.band") == "a"


# ---------------------------------------------------------------------------
# report rendering
# ---------------------------------------------------------------------------

class TestRenderReport:

    def test_report_contains_verdict_and_phases(self, tmp_path):
        session = {
            "started": 1000000.0, "finished": 1000600.0,
            "profile": "Home", "iface": "wlo1", "cycles": 1,
            "dwell_s": 300, "connect_timeout_s": 90, "band": None,
            "phase_results": [
                {"index": 1, "phase": "real", "cycle": 1,
                 "mac": "a0:88:b4:6c:12:34", "outcome": "rejected",
                 "rssi_min": None, "bands": [],
                 "summary": {"incoming_deauths": 0, "assoc_attempts": 2,
                             "gateway_macs": []}},
                {"index": 2, "phase": "random", "cycle": 1,
                 "mac": "02:11:22:33:44:55", "outcome": "connected_ok",
                 "rssi_min": -63, "bands": ["5 GHz"],
                 "summary": {"incoming_deauths": 0, "assoc_attempts": 1,
                             "gateway_macs": ["1c:73:e2:57:f1:39"]}},
            ],
            "verdict": classify_verdict([
                _pr("real", "rejected"), _pr("random", "connected_ok")]),
            "timeline": [{"kind": "marker", "ts": 1000001.0,
                          "phase": "real#1", "detail": "phase start"}],
        }
        md = render_report_md(session)
        assert "identity_targeted" in md
        assert "## Phases" in md
        assert "`02:11:22:33:44:55`" in md
        assert "## Evidence timeline" in md
        assert "phase start" in md
        assert "Next steps" in md


# ---------------------------------------------------------------------------
# CLI plumbing that works hermetically (events + report paths)
# ---------------------------------------------------------------------------

class TestWifiCliPaths:

    def test_latest_report_path(self, tmp_path):
        d = tmp_path / "abtest"
        d.mkdir()
        assert il.latest_report_path() is None
        (d / "20260101-000000-report.md").write_text("# r1")
        (d / "20260102-000000-report.md").write_text("# r2")
        assert il.latest_report_path().name == "20260102-000000-report.md"

    def test_main_wifi_events_and_report(self, tmp_path, monkeypatch, capsys):
        import net_defender as nd
        ev = tmp_path / "link-evidence.jsonl"
        monkeypatch.setattr(nd, "Path", __import__("pathlib").Path)
        ev.write_text(json.dumps(
            {"kind": "deauth", "ts": 1.0, "iso": "2026-10-16 10:00:00",
             "reason": 7, "locally_generated": 0,
             "detail": "CTRL-EVENT-DISCONNECTED"}) + "\n")
        rc = nd.main_wifi(["events", "10", "--kind", "deauth"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "deauth" in out and "reason=7" in out
        # report path
        d = tmp_path / "abtest"
        d.mkdir()
        (d / "20260101-000000-report.md").write_text("# REPORT BODY")
        rc = nd.main_wifi(["report"])
        assert rc == 0
        assert "REPORT BODY" in capsys.readouterr().out
