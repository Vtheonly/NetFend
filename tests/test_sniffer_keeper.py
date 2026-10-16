"""P-42 SnifferKeeper + P-41 singleton lock — live report 2026-10-16.

A brief Wi-Fi link flap closed every guard socket (Scapy: '[Errno 100]
Network is down') and the guards stayed blind until restart. The keeper
supervises and rebuilds sniffers bound to the CURRENT interface; the
engine lock stops the systemd service and a manual run from fighting.
"""
import threading

import pytest

from netfend.utils.sniffer_keeper import (
    SnifferKeeper, ALIVE, RESTORED, DEFERRED, FAILED,
    MAX_CONSECUTIVE_RESTARTS,
)


class FakeSniffer:
    """Mimics AsyncSniffer liveness semantics: `.thread` alive or dead."""

    def __init__(self, alive=True):
        self.stopped = False
        if alive:
            self._alive_evt = threading.Event()
            self.thread = threading.Thread(
                target=self._alive_evt.wait, daemon=True)
            self.thread.start()
        else:
            self.thread = threading.Thread(target=lambda: None, daemon=True)
            # never started -> is_alive() False

    def stop(self):
        self.stopped = True
        evt = getattr(self, "_alive_evt", None)
        if evt is not None:
            evt.set()

    def start(self):
        pass  # AsyncSniffer.start() equivalent (thread already running)


class FakeNm:
    def __init__(self, iface="wlan0"):
        self.state = {"interface": iface, "my_ip": "192.168.1.50",
                      "my_mac": "aa:bb:cc:dd:ee:ff"}

    def snapshot(self):
        return dict(self.state)


class TestSnifferKeeper:
    def _keeper(self, events, sniffer=None, iface="wlan0"):
        state = {"sniffer": sniffer, "built": []}
        nm = FakeNm(iface)

        def build(i):
            state["built"].append(i)
            return FakeSniffer(alive=True)

        keeper = SnifferKeeper(
            events, nm, "arp",
            get=lambda: state["sniffer"],
            build=build,
            set_=lambda s: state.__setitem__("sniffer", s))
        return keeper, state

    def test_alive_sniffer_untouched(self, events):
        keeper, state = self._keeper(events, sniffer=FakeSniffer(alive=True))
        assert keeper.check_and_restore() == ALIVE
        assert state["built"] == []

    def test_dead_sniffer_restarted_on_current_iface(self, events):
        keeper, state = self._keeper(events, sniffer=FakeSniffer(alive=False),
                                     iface="wlp3s0")
        assert keeper.check_and_restore() == RESTORED
        assert state["built"] == ["wlp3s0"]      # bound to CURRENT iface
        assert state["sniffer"] is not None
        assert state["sniffer"].thread.is_alive()
        restarted = [e for e in events.query(limit=10)
                     if e["kind"] == "arp.sniffer_restarted"]
        assert restarted

    def test_dead_sniffer_deferred_when_identity_unknown(self, events):
        keeper, state = self._keeper(events, sniffer=FakeSniffer(alive=False))
        keeper.nm.state["interface"] = None       # link down
        assert keeper.check_and_restore() == DEFERRED
        assert state["built"] == []               # no restart attempt

    def test_build_failure_is_bounded(self, events):
        state = {"sniffer": FakeSniffer(alive=False), "built": []}

        def exploding_build(iface):
            raise RuntimeError("cannot bind")

        keeper = SnifferKeeper(
            events, FakeNm(), "arp",
            get=lambda: state["sniffer"], build=exploding_build,
            set_=lambda s: None)
        assert keeper.check_and_restore() == FAILED

    def test_gives_up_after_consecutive_restarts(self, events):
        keeper, state = self._keeper(events, sniffer=None)
        for _ in range(MAX_CONSECUTIVE_RESTARTS - 1):
            assert keeper._note(RESTORED) is True
        # the MAX_CONSECUTIVE_RESTARTS-th consecutive restart stops it
        assert keeper._note(RESTORED) is False
        assert keeper.gave_up is True
        gave_up = [e for e in events.query(limit=10)
                   if e["kind"] == "arp.sniffer_gave_up"]
        assert gave_up
        # a healthy tick resets the counter
        keeper2, _ = self._keeper(events)
        keeper2._note(RESTORED)
        keeper2._note(ALIVE)
        assert keeper2._restarts == 0

    def test_no_resurrection_after_stop(self, events):
        keeper, state = self._keeper(events, sniffer=FakeSniffer(alive=False))
        keeper.stop()
        assert keeper.check_and_restore() == ALIVE   # refuses to restart
        assert state["built"] == []


class TestEngineSingletonLock:
    """P-41: service + manual run must never coexist (flock-based)."""

    def test_second_acquire_conflicts(self, tmp_path):
        from net_defender import _acquire_engine_lock
        path = str(tmp_path / "engine.lock")
        fd, conflict = _acquire_engine_lock(path)
        assert fd is not None and conflict is None
        try:
            fd2, conflict2 = _acquire_engine_lock(path)
            assert fd2 is None
            assert conflict2 is not None          # holder pid reported
            assert conflict2.isdigit()
        finally:
            import os
            os.close(fd)                          # kernel releases flock

    def test_lock_released_after_close(self, tmp_path):
        import os
        from net_defender import _acquire_engine_lock
        path = str(tmp_path / "engine.lock")
        fd, _ = _acquire_engine_lock(path)
        os.close(fd)                              # crash-equivalent release
        fd2, conflict2 = _acquire_engine_lock(path)
        assert fd2 is not None and conflict2 is None
        os.close(fd2)

    def test_run_service_refuses_when_locked(self, tmp_path, monkeypatch):
        import net_defender
        monkeypatch.setattr(net_defender.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            net_defender, "_acquire_engine_lock",
            lambda path="/run/netfend.engine.lock": (None, "4242"))
        assert net_defender.run_service() == 1    # refused, non-zero exit

    def test_run_service_non_root_refused(self, tmp_path, monkeypatch):
        import net_defender
        monkeypatch.setattr(net_defender.os, "geteuid", lambda: 1000)
        assert net_defender.run_service() == 1
