"""Config layering, event store, validators, logging, capabilities."""
import json
import time

import pytest

from netfend.utils import validators as V


class TestConfig:
    def test_defaults_load(self):
        from netfend.utils.config import load_config, cfg
        c = load_config()
        assert c["firewall"]["profile"] == "standard"
        assert cfg("arp", "gateway_confirmations") == 2

    def test_json_overlay(self, tmp_path):
        from netfend.utils.config import load_config
        p = tmp_path / "config.json"
        p.write_text(json.dumps({"firewall": {"profile": "strict"}}))
        c = load_config(p)
        assert c["firewall"]["profile"] == "strict"
        # untouched sections keep defaults
        assert c["arp"]["gateway_confirmations"] == 2

    def test_unknown_keys_warn_not_crash(self, tmp_path, capsys):
        from netfend.utils.config import load_config
        p = tmp_path / "config.json"
        p.write_text(json.dumps({"nonexistent_section": {"x": 1},
                                 "firewall": {"bogus_key": 5}}))
        c = load_config(p)
        out = capsys.readouterr().out
        assert "unknown config key" in out
        assert c["firewall"]["profile"] == "standard"

    def test_broken_json_falls_back(self, tmp_path):
        from netfend.utils.config import load_config
        p = tmp_path / "config.json"
        p.write_text("{not json!!")
        c = load_config(p)
        assert c["firewall"]["profile"] == "standard"

    def test_dry_run_env_override(self, monkeypatch):
        from netfend.utils.config import load_config, cfg
        monkeypatch.setenv("NETFEND_DRY_RUN", "1")
        load_config()
        assert cfg("general", "dry_run") is True

    def test_set_config_validates(self):
        from netfend.utils.config import load_config, set_config
        load_config()
        with pytest.raises(KeyError):
            set_config("nope", "x", 1)
        with pytest.raises(KeyError):
            set_config("firewall", "nope", 1)
        set_config("firewall", "profile", "strict")
        from netfend.utils.config import cfg
        assert cfg("firewall", "profile") == "strict"


class TestValidators:
    def test_mac(self):
        assert V.valid_mac("AA:BB:CC:DD:EE:FF")
        assert V.valid_mac("aa:bb:cc:dd:ee:ff")
        assert not V.valid_mac("aa:bb:cc:dd:ee")
        assert not V.valid_mac("gg:bb:cc:dd:ee:ff")
        assert not V.valid_mac(None)
        assert V.normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
        with pytest.raises(ValueError):
            V.normalize_mac("bad")

    def test_ipv4(self):
        assert V.valid_ipv4("192.168.1.1")
        assert V.valid_ipv4("0.0.0.0")
        assert not V.valid_ipv4("256.1.1.1")
        assert not V.valid_ipv4("1.1.1")
        assert not V.valid_ipv4("not-an-ip")
        assert not V.valid_ipv4(None)

    def test_interface(self):
        assert V.valid_interface("wlan0")
        assert V.valid_interface("enp3s0f1")
        assert not V.valid_interface("bad iface!")
        assert not V.valid_interface("x" * 20)

    def test_ports(self):
        assert V.valid_port(22) and V.valid_port("8080")
        assert not V.valid_port(0) and not V.valid_port(70000)
        assert not V.valid_port("abc")
        assert V.valid_ports([53, 67, 68])
        assert not V.valid_ports([53, "ftp"])


class TestEventStore:
    def test_emit_and_query(self, events):
        events.emit_simple("arp.gateway_spoof", "critical", "confirmed",
                           "test event", source="arp", foo="bar")
        got = events.query()
        assert len(got) == 1
        assert got[0]["kind"] == "arp.gateway_spoof"
        assert got[0]["evidence"]["foo"] == "bar"
        assert got[0]["severity"] == "critical"

    def test_query_filters(self, events):
        now = time.time()
        events.emit_simple("arp.x", "critical", "confirmed", "a")
        events.emit_simple("dns.y", "info", "unverified", "b")
        events.emit_simple("arp.z", "warning", "suspected", "c")
        assert len(events.query(min_severity="warning")) == 2
        assert len(events.query(kind_prefix="arp.")) == 2
        assert len(events.query(kind_prefix="dns.")) == 1
        assert len(events.query(since=now + 10)) == 0
        assert len(events.query(limit=2)) == 2

    def test_ring_respects_maxlen(self, tmp_path):
        from netfend.models.events import EventStore
        s = EventStore(path=tmp_path / "e.jsonl", ring_size=5)
        for i in range(20):
            s.emit_simple("k.x", "info", "unverified", f"e{i}")
        assert len(s.query(limit=100)) == 5
        assert s.query()[0]["summary"] == "e19"  # newest first
        s.close()

    def test_jsonl_persistence_and_rotation(self, tmp_path):
        from netfend.models.events import EventStore
        p = tmp_path / "e.jsonl"
        s = EventStore(path=p, file_max_bytes=512)
        for i in range(40):
            s.emit_simple("k.x", "info", "unverified", f"event number {i}" * 3)
        s.close()
        # rotation produced the .1 file or kept under cap
        assert p.exists()
        assert p.stat().st_size <= 512 or (tmp_path / "e.jsonl.1").exists()

    def test_unwritable_path_still_works_in_memory(self, tmp_path):
        from netfend.models.events import EventStore
        s = EventStore(path=tmp_path / "no" / "perm" / "e.jsonl")
        # mkdir should succeed (parents=True)... use a file-as-dir trick
        blocker = tmp_path / "blocker"
        blocker.write_text("x")
        s2 = EventStore(path=blocker / "sub" / "e.jsonl")
        s2.emit_simple("k", "info", "confirmed", "still works")
        assert len(s2.query()) == 1
        s.close()
        s2.close()

    def test_dedup_folds_identical_bursts(self, tmp_path):
        """P-21 live-fire regression: 106 identical gateway_change events
        became one row with a repeat_count."""
        from netfend.models.events import EventStore
        s = EventStore(path=tmp_path / "e.jsonl", dedup_window_s=10)
        for _ in range(50):  # 50 identical events within the window
            s.emit_simple("arp.gateway_change", "notice", "unverified",
                          "Gateway 192.168.100.1 now announces MAC X")
        rows = s.query()
        assert len(rows) == 1
        assert rows[0]["repeat_count"] == 49
        # different summaries are NOT folded
        s.emit_simple("arp.gateway_change", "notice", "unverified",
                      "Gateway 10.0.0.1 now announces MAC Y")
        assert len(s.query()) == 2
        s.close()

    def test_dedup_window_expiry_creates_new_event(self, tmp_path):
        import time as _time
        from netfend.models.events import EventStore, SecurityEvent
        s = EventStore(path=tmp_path / "e.jsonl", dedup_window_s=10)
        base = _time.time()
        s.emit(SecurityEvent(kind="k.x", severity="info",
                             confidence="confirmed", summary="same",
                             timestamp=base))
        s.emit(SecurityEvent(kind="k.x", severity="info",
                             confidence="confirmed", summary="same",
                             timestamp=base + 5))     # inside window
        s.emit(SecurityEvent(kind="k.x", severity="info",
                             confidence="confirmed", summary="same",
                             timestamp=base + 30))    # outside window
        rows = s.query()
        assert len(rows) == 2
        assert rows[0]["repeat_count"] == 0            # newest: fresh burst
        assert rows[1]["repeat_count"] == 1            # first burst folded 2
        s.close()

    def test_dedup_jsonl_keeps_first_occurrence(self, tmp_path):
        from netfend.models.events import EventStore
        p = tmp_path / "e.jsonl"
        s = EventStore(path=p)
        for _ in range(20):
            s.emit_simple("k.flap", "notice", "unverified", "identical")
        s.close()
        lines = [l for l in p.read_text().splitlines() if l.strip()]
        assert len(lines) == 1  # burst persisted once, not 20 times

    def test_ring_seeded_from_jsonl_on_restart(self, tmp_path):
        """CLI --events bug: a fresh EventStore showed nothing because the
        JSONL history was never loaded into the ring."""
        from netfend.models.events import EventStore
        p = tmp_path / "e.jsonl"
        s = EventStore(path=p)
        for i in range(5):
            s.emit_simple("k.hist", "info", "confirmed", f"history {i}")
        s.close()
        # simulate a restart (what `netfend --events` does)
        s2 = EventStore(path=p)
        rows = s2.query()
        assert len(rows) == 5
        assert rows[0]["summary"] == "history 4"   # newest first
        s2.close()

    def test_corrupt_jsonl_lines_skipped(self, tmp_path):
        from netfend.models.events import EventStore
        p = tmp_path / "e.jsonl"
        p.write_text('{"kind": "k.ok", "severity": "info", '
                     '"confidence": "confirmed", "summary": "good"}\n'
                     'NOT JSON AT ALL\n'
                     '{"kind": "k.ok2", "severity": "info", '
                     '"confidence": "confirmed", "summary": "also good"}\n')
        s = EventStore(path=p)
        assert len(s.query()) == 2
        s.close()


class TestLogging:
    def test_setup_and_rotate_config(self, tmp_path, monkeypatch):
        from netfend.utils import logging as L
        from netfend.utils.config import load_config
        load_config()
        # logging.py holds its own LOG_FILE reference — patch it there
        monkeypatch.setattr(L, "LOG_FILE", tmp_path / "netfend.log")
        L._configured = False
        L._logger.handlers.clear()
        logger = L.setup_logging()
        L.log_info("hello info")
        L.log_warn("hello warn")
        L.log_err("hello err")
        L.log_alert("hello alert")
        assert (tmp_path / "netfend.log").exists()

    def test_no_colorama_still_imports(self):
        from netfend.utils import logging as L
        # on this test env colorama may be absent — module must still import
        assert callable(L.log_info)


class TestCapabilities:
    def test_probe_shape(self):
        from netfend.utils import capabilities
        caps = capabilities.probe()
        for key in ("root", "linux", "scapy", "psutil", "nft", "ip", "ping"):
            assert key in caps
        assert isinstance(caps["root"], bool)

    def test_summary_notes(self):
        from netfend.utils import capabilities
        s = capabilities.summary()
        assert "capabilities" in s and isinstance(s["notes"], list)


class TestConfigNoDefaultsPollution:
    """P-31 regression: runtime set_config() must never mutate DEFAULTS.

    Found live 2026-10-16 while testing the hardening engine wiring: a
    shallow _deep_merge let the effective config SHARE nested dicts with
    DEFAULTS, so a set_config('general','dry_run',True) in one test (or a
    dashboard 'reload' in production) permanently changed the defaults
    for every later load_config() in the same process.
    """

    def test_set_config_does_not_mutate_defaults(self):
        import copy
        import netfend.utils.config as config_mod
        from netfend.utils.config import DEFAULTS, load_config, set_config
        snapshot = copy.deepcopy(DEFAULTS)
        load_config()
        set_config("general", "dry_run", True)
        set_config("arp", "corrective_arp_max", 99)
        assert DEFAULTS == snapshot, "DEFAULTS was mutated by set_config"

    def test_reload_does_not_inherit_previous_overrides(self):
        import netfend.utils.config as config_mod
        from netfend.utils.config import load_config, set_config, cfg
        load_config()
        set_config("general", "dry_run", True)
        assert cfg("general", "dry_run") is True
        config_mod._config = {}          # simulate a config reload
        assert load_config()["general"]["dry_run"] is False
