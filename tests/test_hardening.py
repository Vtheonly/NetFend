"""KernelHardener — sysctl enforcement + restore contract (ADR-007).

All /proc/sys access is pointed at a fake filesystem under tmp_path:
these tests verify the DECISION LOGIC (what gets written, what gets
restored, what is refused), never the real kernel.
"""
import json

import pytest

from netfend.services.hardening import KernelHardener, build_param_list

from netfend.utils import capabilities


@pytest.fixture()
def fake_proc(tmp_path):
    """A miniature /proc/sys populated with kernel-default-ish values."""
    base = tmp_path / "proc"
    defaults = {
        "net/ipv4/conf/all/accept_redirects": "1",
        "net/ipv4/conf/default/accept_redirects": "1",
        "net/ipv4/conf/all/secure_redirects": "1",
        "net/ipv4/conf/default/secure_redirects": "1",
        "net/ipv4/conf/all/accept_source_route": "0",
        "net/ipv4/conf/default/accept_source_route": "0",
        "net/ipv4/conf/all/send_redirects": "1",
        "net/ipv4/conf/default/send_redirects": "1",
        "net/ipv4/icmp_echo_ignore_broadcasts": "1",
        "net/ipv4/conf/all/rp_filter": "2",
        "net/ipv4/conf/default/rp_filter": "2",
        "net/ipv6/conf/all/accept_redirects": "1",
        "net/ipv6/conf/default/accept_redirects": "1",
    }
    for rel, value in defaults.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value + "\n")
    return base


@pytest.fixture()
def hardener(events, tmp_path, fake_proc, monkeypatch):
    monkeypatch.setattr(capabilities, "have", lambda name: True)
    h = KernelHardener(events, proc_base=str(fake_proc),
                       state_path=tmp_path / "state.json")
    return h


def read(fake_proc, rel):
    return (fake_proc / rel).read_text().strip()


class TestBuildParamList:
    def test_strict_includes_rp_filter_1(self):
        params = dict(build_param_list("strict"))
        assert params["net/ipv4/conf/all/rp_filter"] == "1"
        assert params["net/ipv4/conf/all/accept_redirects"] == "0"
        assert params["net/ipv6/conf/all/accept_redirects"] == "0"
        assert "net/ipv4/conf/all/accept_source_route" in params

    def test_loose_uses_2(self):
        params = dict(build_param_list("loose"))
        assert params["net/ipv4/conf/all/rp_filter"] == "2"

    def test_preserve_omits_rp_filter(self):
        params = dict(build_param_list("preserve"))
        assert "net/ipv4/conf/all/rp_filter" not in params
        assert "net/ipv4/conf/default/rp_filter" not in params

    def test_unknown_mode_raises(self):
        with pytest.raises(ValueError):
            build_param_list("yolo")

    def test_no_accept_ra_owned_here(self):
        """accept_ra belongs to the IPv6 guard (T-32), never hardening."""
        for rel, _ in build_param_list("strict"):
            assert "accept_ra" not in rel


class TestApplyAndRestore:
    def test_apply_writes_and_saves_originals(self, hardener, fake_proc,
                                              tmp_path):
        assert hardener.apply() is True
        assert read(fake_proc, "net/ipv4/conf/all/accept_redirects") == "0"
        assert read(fake_proc, "net/ipv4/conf/all/rp_filter") == "1"
        assert read(fake_proc, "net/ipv6/conf/all/accept_redirects") == "0"
        state = json.loads((tmp_path / "state.json").read_text())
        assert state["net/ipv4/conf/all/accept_redirects"] == "1"
        assert state["net/ipv4/conf/all/rp_filter"] == "2"
        ev = [e for e in hardener.events.query(limit=10)
              if e["kind"] == "hardening.applied"]
        assert ev and ev[0]["evidence"]["applied"]  # evidence in the event

    def test_restore_returns_originals(self, hardener, fake_proc, tmp_path):
        hardener.apply()
        hardener.restore()
        assert read(fake_proc, "net/ipv4/conf/all/accept_redirects") == "1"
        assert read(fake_proc, "net/ipv4/conf/all/rp_filter") == "2"
        assert not (tmp_path / "state.json").exists()   # state cleared
        ev = [e for e in hardener.events.query(limit=10)
              if e["kind"] == "hardening.restored"]
        assert ev

    def test_restore_on_stop_false_keeps_values(self, hardener, fake_proc,
                                               events):
        from netfend.utils.config import load_config, set_config
        load_config()
        set_config("hardening", "restore_on_stop", False)
        hardener.apply()
        hardener.restore()
        assert read(fake_proc, "net/ipv4/conf/all/accept_redirects") == "0"

    def test_missing_knob_is_skipped_not_failed(self, hardener, fake_proc):
        (fake_proc / "net/ipv4/icmp_echo_ignore_broadcasts").unlink()
        ok = hardener.apply()
        assert ok is True
        assert "net/ipv4/icmp_echo_ignore_broadcasts" in \
            hardener.last_result["skipped"]

    def test_crash_recovery_restores_stale_state_first(self, events, tmp_path,
                                                       fake_proc, monkeypatch):
        monkeypatch.setattr(capabilities, "have", lambda name: True)
        # scenario: a previous run hardened the kernel, then crashed
        # WITHOUT restoring. Current values are the leftover hardened ones.
        (fake_proc / "net/ipv4/conf/all/accept_redirects").write_text("0\n")
        (fake_proc / "net/ipv4/conf/all/rp_filter").write_text("1\n")
        # the crashed run's state file holds the TRUE pre-hardening values
        stale = {"net/ipv4/conf/all/accept_redirects": "1",
                 "net/ipv4/conf/all/rp_filter": "2"}
        (tmp_path / "state.json").write_text(json.dumps(stale))
        h = KernelHardener(events, proc_base=str(fake_proc),
                           state_path=tmp_path / "state.json")
        h.apply()
        # the saved originals must be the TRUE pre-hardening values,
        # not the leftover hardened ones
        state = json.loads((tmp_path / "state.json").read_text())
        assert state["net/ipv4/conf/all/accept_redirects"] == "1"
        assert state["net/ipv4/conf/all/rp_filter"] == "2"
        assert read(fake_proc, "net/ipv4/conf/all/accept_redirects") == "0"

    def test_restore_refuses_paths_outside_net(self, events, tmp_path,
                                               fake_proc, monkeypatch):
        monkeypatch.setattr(capabilities, "have", lambda name: True)
        evil = {"../tmp/evil": "1", "proc/self/mem": "1",
                "net/ipv4/conf/all/accept_redirects": "1"}
        (tmp_path / "state.json").write_text(json.dumps(evil))
        h = KernelHardener(events, proc_base=str(fake_proc),
                           state_path=tmp_path / "state.json")
        h.restore()   # must not raise, must not write outside net/
        assert read(fake_proc, "net/ipv4/conf/all/accept_redirects") == "1"
        assert not (tmp_path / "evil").exists()

    def test_status_shape(self, hardener):
        hardener.apply()
        s = hardener.status()
        assert s["enabled"] is True and s["active"] is True
        assert s["rp_filter_mode"] == "strict"
        assert "net/ipv4/conf/all/accept_redirects" in s["enforced"]


class TestGates:
    def test_non_root_noop(self, events, tmp_path, fake_proc, monkeypatch):
        monkeypatch.setattr(capabilities, "have", lambda name: False)
        h = KernelHardener(events, proc_base=str(fake_proc),
                           state_path=tmp_path / "state.json")
        assert h.apply() is False
        assert read(fake_proc, "net/ipv4/conf/all/accept_redirects") == "1"
        ev = [e for e in events.query(limit=10)
              if e["kind"] == "hardening.unavailable"]
        assert ev

    def test_dry_run_noop(self, events, tmp_path, fake_proc, monkeypatch):
        from netfend.utils.config import load_config, set_config
        load_config()
        set_config("general", "dry_run", True)
        monkeypatch.setattr(capabilities, "have", lambda name: True)
        h = KernelHardener(events, proc_base=str(fake_proc),
                           state_path=tmp_path / "state.json")
        assert h.apply() is False
        assert read(fake_proc, "net/ipv4/conf/all/accept_redirects") == "1"

    def test_config_disabled_noop(self, events, tmp_path, fake_proc,
                                  monkeypatch):
        from netfend.utils.config import load_config, set_config
        load_config()
        set_config("hardening", "enabled", False)
        monkeypatch.setattr(capabilities, "have", lambda name: True)
        h = KernelHardener(events, proc_base=str(fake_proc),
                           state_path=tmp_path / "state.json")
        assert h.apply() is False
        assert read(fake_proc, "net/ipv4/conf/all/accept_redirects") == "1"


class TestEngineWiring:
    def test_engine_applies_and_restores_hardening(self, tmp_path, monkeypatch):
        """The orchestrator must call hardener.apply() in the protection
        path and hardener.restore() on stop (ADR-007 contract)."""
        from netfend.models.events import EventStore
        from netfend.services.defense_engine import DefenseEngine
        store = EventStore(path=tmp_path / "ev.jsonl")
        calls = []
        try:
            engine = DefenseEngine(events=store)
            monkeypatch.setattr(engine.hardener, "apply",
                                lambda: calls.append("apply") or True)
            monkeypatch.setattr(engine.hardener, "restore",
                                lambda: calls.append("restore"))
            engine._apply_protections()
            engine.running = True   # simulate a started engine for stop()
            engine.stop()
            assert "apply" in calls and "restore" in calls
        finally:
            store.close()
