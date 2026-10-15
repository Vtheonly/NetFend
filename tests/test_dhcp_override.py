"""DHCP option-override rejection (P-33, zero-trust threat model).

A rogue DHCP server OR a compromised router can push option 3 (router)
or option 6 (DNS) that steers traffic to an attacker proxy. The
evaluator must REJECT such pushes (keep the trusted baseline, emit
critical events, feed intel, trigger the engine's line-rate drop)
while still learning gateway-consistent changes.
"""
import time

import pytest

from netfend.services.dhcp_guard import DhcpEvaluator, DhcpGuard, is_lan_ip

GW = "192.168.1.1"
ATTACKER_ROUTER = "192.168.1.66"     # not the verified gateway
SERVER_MAC = "1c:73:e2:58:77:17"
MY = {"ip": "192.168.1.50", "mac": "aa:aa:aa:aa:aa:aa"}


class FakeNm:
    def snapshot(self):
        return {"interface": "wlan0", "my_ip": MY["ip"], "my_mac": MY["mac"],
                "gateway_ip": GW, "gateway_mac": "11:11:11:11:11:11"}


class FakeIntel:
    def __init__(self):
        self.calls = []

    def record_attack(self, mac, technique, spoofed_ip=None):
        self.calls.append((mac, technique, spoofed_ip))
        return None


def obs(router=GW, dns=None, server_id=GW, mac=SERVER_MAC, msg="ack"):
    return {
        "server_ip": server_id,
        "server_mac": mac,
        "message_type": msg,
        "your_ip": MY["ip"],
        "options": {"router": router,
                    "dns": dns if dns is not None else ["1.1.1.1", "9.9.9.9"],
                    "server_id": server_id},
    }


def learned_evaluator():
    """Evaluator past its learning window with a trusted baseline."""
    ev = DhcpEvaluator(gateway={"ip": GW})
    ev.evaluate(obs(), 100.0)        # learning observation 1
    ev.evaluate(obs(), 101.0)        # learning observation 2
    assert ev.baseline_router == GW
    assert ev.baseline_dns == ["1.1.1.1", "9.9.9.9"]
    return ev


class TestIsLanIp:
    def test_private_ranges(self):
        assert is_lan_ip("192.168.1.1")
        assert is_lan_ip("10.0.0.1")
        assert is_lan_ip("172.16.5.5")
        assert is_lan_ip("169.254.1.1")

    def test_public_and_garbage(self):
        assert not is_lan_ip("1.1.1.1")
        assert not is_lan_ip("9.9.9.9")
        assert not is_lan_ip("127.0.0.1")     # loopback is not a LAN target
        assert not is_lan_ip("not-an-ip")


class TestRouterOverride:
    def test_override_rejected_baseline_kept(self):
        ev = learned_evaluator()
        events = ev.evaluate(obs(router=ATTACKER_ROUTER), 200.0)
        kinds = [e["kind"] for e in events]
        assert "dhcp.router_override" in kinds
        ovr = next(e for e in events if e["kind"] == "dhcp.router_override")
        assert ovr["severity"] == "critical"
        assert ovr["confidence"] == "confirmed"
        assert ovr["evidence"]["pushed_router"] == ATTACKER_ROUTER
        assert ovr["evidence"]["verified_gateway"] == GW
        # REJECTED: the override must NOT become the new baseline
        assert ev.baseline_router == GW

    def test_override_repeats_do_not_learn(self):
        ev = learned_evaluator()
        for t in range(200, 260):
            ev.evaluate(obs(router=ATTACKER_ROUTER), float(t))
        assert ev.baseline_router == GW

    def test_gateway_consistent_change_still_learned(self):
        """A router option that equals the verified gateway (legit
        reconfig) keeps the old warning path AND updates the baseline."""
        ev = learned_evaluator()
        ev.baseline_router = "192.168.1.254"   # e.g. old DHCP value
        events = ev.evaluate(obs(router=GW), 200.0)
        kinds = [e["kind"] for e in events]
        assert "dhcp.router_option_change" in kinds
        assert "dhcp.router_override" not in kinds
        assert ev.baseline_router == GW         # learned

    def test_no_gateway_context_keeps_old_behavior(self):
        """Without verified-gateway context we cannot confirm an override:
        keep the ambiguous warning, do not claim 'confirmed'."""
        ev = learned_evaluator()
        ev.gateway = {}
        events = ev.evaluate(obs(router=ATTACKER_ROUTER), 200.0)
        kinds = [e["kind"] for e in events]
        assert "dhcp.router_option_change" in kinds
        assert ev.baseline_router == ATTACKER_ROUTER  # ambiguous: learned


class TestDnsOverride:
    def test_public_to_lan_override_rejected(self):
        ev = learned_evaluator()
        events = ev.evaluate(obs(dns=["192.168.1.66"]), 200.0)
        kinds = [e["kind"] for e in events]
        assert "dhcp.dns_override" in kinds
        ovr = next(e for e in events if e["kind"] == "dhcp.dns_override")
        assert ovr["severity"] == "critical"
        assert ev.baseline_dns == ["1.1.1.1", "9.9.9.9"]   # kept

    def test_lan_to_lan_change_is_notice(self):
        ev = learned_evaluator()
        ev.baseline_dns = [GW]                  # LAN baseline (router DNS)
        events = ev.evaluate(obs(dns=["192.168.1.2"]), 200.0)
        kinds = [e["kind"] for e in events]
        assert "dhcp.dns_option_change" in kinds
        assert "dhcp.dns_override" not in kinds
        assert ev.baseline_dns == ["192.168.1.2"]          # learned

    def test_public_to_public_change_is_notice(self):
        ev = learned_evaluator()
        events = ev.evaluate(obs(dns=["8.8.8.8", "8.8.4.4"]), 200.0)
        kinds = [e["kind"] for e in events]
        assert "dhcp.dns_option_change" in kinds
        assert "dhcp.dns_override" not in kinds


class TestGuardIntegration:
    def test_override_feeds_intel_and_callback(self, events):
        intel = FakeIntel()
        callbacks = []
        guard = DhcpGuard(FakeNm(), events, intel=intel,
                          on_override=lambda ev: callbacks.append(ev))
        # learning
        guard.process_observation(obs())
        guard.process_observation(obs())
        # override attempt
        out = guard.process_observation(obs(router=ATTACKER_ROUTER))
        assert any(e["kind"] == "dhcp.router_override" for e in out)
        assert any(m == SERVER_MAC and t == "dhcp.router_override"
                   for m, t, _ in intel.calls)
        assert callbacks and callbacks[0]["evidence"]["pushed_router"] == \
            ATTACKER_ROUTER
        # the event store carries the critical event for the dashboard
        evs = [e for e in events.query(limit=20)
               if e["kind"] == "dhcp.router_override"]
        assert evs

    def test_rogue_server_feeds_intel(self, events):
        intel = FakeIntel()
        guard = DhcpGuard(FakeNm(), events, intel=intel)
        guard.process_observation(obs())
        guard.process_observation(obs())
        # a DIFFERENT unknown server shows up
        guard.process_observation(obs(mac="de:ad:be:ef:00:99",
                                       server_id="192.168.1.99"))
        assert any(m == "de:ad:be:ef:00:99" and t == "dhcp.rogue_server"
                   for m, t, _ in intel.calls)


class TestOverrideDropRules:
    def test_add_override_drop_commands(self, events, monkeypatch):
        """The firewall must add input+output drops for the target IP,
        refusing invalid addresses and skipping when the table is off."""
        from netfend.services.firewall import FirewallManager
        calls = []

        class FakeResult:
            returncode = 0
            stderr = ""

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return FakeResult()

        import netfend.services.firewall as fw_mod
        monkeypatch.setattr(fw_mod.subprocess, "run", fake_run)
        monkeypatch.setattr(fw_mod.capabilities, "have", lambda n: True)
        fm = FirewallManager(FakeNm(), events)
        fm.applied = True
        assert fm.add_override_drop("192.168.1.66") is True
        joined = [" ".join(c) for c in calls]
        assert any("input" in j and "saddr 192.168.1.66" in j for j in joined)
        assert any("output" in j and "daddr 192.168.1.66" in j for j in joined)
        # idempotent
        assert fm.add_override_drop("192.168.1.66") is True
        assert fm.override_drops == ["192.168.1.66"]
        # invalid IP refused
        assert fm.add_override_drop("999.1.1.1") is False
        # not applied -> a NEW ip is refused (already-dropped stays True)
        fm.applied = False
        assert fm.add_override_drop("192.168.1.77") is False


class TestEngineWiring:
    def test_engine_drops_override_target(self, tmp_path, monkeypatch):
        """Engine._on_dhcp_override must call firewall.add_override_drop
        with the pushed router (P-33 contract) — off the sniffer thread."""
        from netfend.models.events import EventStore
        from netfend.services.defense_engine import DefenseEngine
        store = EventStore(path=tmp_path / "ev.jsonl")
        try:
            engine = DefenseEngine(events=store)
            got = {}
            monkeypatch.setattr(engine.firewall, "add_override_drop",
                                lambda ip: got.setdefault("ip", ip) or True)
            engine._on_dhcp_override({
                "kind": "dhcp.router_override",
                "evidence": {"pushed_router": ATTACKER_ROUTER}})
            deadline = time.time() + 2
            while time.time() < deadline and "ip" not in got:
                time.sleep(0.02)
            assert got.get("ip") == ATTACKER_ROUTER
        finally:
            store.close()
