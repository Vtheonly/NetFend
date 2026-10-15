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
