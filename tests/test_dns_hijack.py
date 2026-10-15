"""DNS hijack detection + zero-trust recommendations (P-34).

A compromised router can hijack port 53 / its own resolver and
fabricate answers (captive portals, DNS steering). Detection: a random
label under `.invalid` (RFC 2606: guaranteed non-existent) is resolved
via the SYSTEM resolver and, when that unexpectedly answers, directly
against public resolvers (stdlib UDP, bypassing the local chain). A
system answer + direct NXDOMAIN = CONFIRMED fabrication.
"""
import socket
import struct

import pytest

from netfend.services.dns_guard import (
    DnsEvaluator, DnsGuard, RECOMMENDATIONS,
    build_dns_query, parse_dns_response, is_lan_resolver,
    parse_resolv_conf,
)

NOW = 1_000_000.0


class FakeNm:
    def snapshot(self):
        return {"interface": "wlan0", "my_ip": "192.168.1.50",
                "my_mac": "aa:aa:aa:aa:aa:aa",
                "gateway_ip": "192.168.1.1", "gateway_mac": None}


def nxdomain_response(qid=0x4E46, rcode=3, answers=0):
    """Minimal DNS response header (question section optional for parse)."""
    flags = 0x8180 | rcode
    return struct.pack(">HHHHHH", qid, flags, 1, answers, 0, 0)


class TestWireFormat:
    def test_build_query_known_bytes(self):
        q = build_dns_query("a.invalid", qid=0x1234)
        # header: id, flags RD=1, qdcount=1
        assert q[:6] == struct.pack(">HHH", 0x1234, 0x0100, 1)
        # QNAME labels: 1"a" 7"invalid" 0
        assert q[12:12 + 11] == b"\x01a\x07invalid\x00"
        # QTYPE=A(1), QCLASS=IN(1)
        assert q[-4:] == struct.pack(">HH", 1, 1)

    def test_parse_response_fields(self):
        r = parse_dns_response(nxdomain_response(rcode=3, answers=0))
        assert r["rcode"] == 3 and r["answers"] == 0 and r["truncated"] is False
        r2 = parse_dns_response(nxdomain_response(rcode=0, answers=1))
        assert r2["rcode"] == 0 and r2["answers"] == 1

    def test_parse_response_garbage(self):
        assert parse_dns_response(b"short") is None


class TestHijackClassification:
    def test_clean_system_no_event(self):
        ev = DnsEvaluator()
        assert ev.evaluate_hijack(False, None, NOW) == []

    def test_confirmed_fabrication(self):
        ev = DnsEvaluator()
        events = ev.evaluate_hijack(True, {"rcode": 3, "answers": 0}, NOW)
        assert events and events[0]["kind"] == "dns.hijack_signature"
        assert events[0]["severity"] == "critical"
        assert events[0]["confidence"] == "confirmed"
        assert events[0]["recommendations"] == RECOMMENDATIONS

    def test_suspected_when_direct_unavailable(self):
        ev = DnsEvaluator()
        events = ev.evaluate_hijack(True, None, NOW)
        assert events[0]["confidence"] == "suspected"
        assert events[0]["evidence"]["direct_check"] == "unavailable"

    def test_weird_public_answer_stays_suspected(self):
        ev = DnsEvaluator()
        events = ev.evaluate_hijack(True, {"rcode": 0, "answers": 2}, NOW)
        assert events[0]["confidence"] == "suspected"

    def test_hijack_cooldown(self):
        ev = DnsEvaluator()
        assert ev.evaluate_hijack(True, {"rcode": 3, "answers": 0}, NOW)
        assert ev.evaluate_hijack(True, {"rcode": 3, "answers": 0},
                                  NOW + 60) == []
        assert ev.evaluate_hijack(True, {"rcode": 3, "answers": 0},
                                  NOW + 400)


class TestDirectQuery:
    def test_direct_query_builds_and_parses(self, events, monkeypatch):
        """The ground-truth query goes to the configured public resolver,
        bypassing the system resolver entirely."""
        g = DnsGuard(FakeNm(), events)
        sent = {}

        class FakeSock:
            def __init__(self):
                self.timeout = None

            def settimeout(self, t):
                self.timeout = t

            def sendto(self, data, addr):
                sent["data"], sent["addr"] = data, addr

            def recvfrom(self, n):
                return nxdomain_response(), ("1.1.1.1", 53)

            def close(self):
                pass

        monkeypatch.setattr(socket, "socket",
                            lambda *a, **kw: FakeSock())
        out = g._direct_query("netfend-abc.invalid", 2.0)
        assert out == {"rcode": 3, "answers": 0, "truncated": False,
                       "via": "1.1.1.1"}
        assert sent["addr"] == ("1.1.1.1", 53)
        assert parse_dns_response(sent["data"])["rcode"] == 0  # query flags

    def test_direct_query_unreachable_returns_none(self, events, monkeypatch):
        g = DnsGuard(FakeNm(), events)

        class DeadSock:
            def settimeout(self, t):
                pass

            def sendto(self, *a):
                raise OSError("blocked")

            def close(self):
                pass

        monkeypatch.setattr(socket, "socket", lambda *a, **kw: DeadSock())
        assert g._direct_query("x.invalid", 0.1) is None


class TestProbeRoundIntegration:
    def test_hijack_round_emits_event_with_recommendations(self, events,
                                                            monkeypatch):
        g = DnsGuard(FakeNm(), events)
        monkeypatch.setattr(g, "_probe",
                            lambda d, t: {"ok": True, "elapsed_s": 0.01})
        monkeypatch.setattr(g, "_run_hijack_check",
                            lambda t: g.events.emit_simple(
                                "dns.hijack_signature", "critical", "confirmed",
                                "fabricated answer",
                                source="dns", recommendations=list(RECOMMENDATIONS),
                                direct_rcode=3, direct_answers=0))
        g._probe_round()
        evs = [e for e in events.query(limit=10)
               if e["kind"] == "dns.hijack_signature"]
        assert evs and evs[0]["evidence"]["recommendations"] == \
            RECOMMENDATIONS

    def test_hijack_check_disabled(self, events, monkeypatch):
        from netfend.utils.config import load_config, set_config
        load_config()
        set_config("dns", "hijack_check", False)
        g = DnsGuard(FakeNm(), events)
        called = []
        monkeypatch.setattr(g, "_run_hijack_check",
                            lambda t: called.append(t))
        monkeypatch.setattr(g, "_probe",
                            lambda d, t: {"ok": True, "elapsed_s": 0.01})
        g._probe_round()
        assert called == []


class TestRecommendations:
    def test_lan_only_resolvers_trigger_guidance(self, events):
        g = DnsGuard(FakeNm(), events)
        g.evaluator.baseline_servers = ["192.168.1.1", "fe80::1"]
        recs = g.recommendations()
        assert recs and any("DNSOverTLS" in r for r in recs)
        assert any("1.1.1.1" in r for r in recs)
        s = g.status()
        assert s["resolvers_lan_only"] is True
        assert s["recommendations"] == recs

    def test_public_resolvers_no_guidance(self, events):
        g = DnsGuard(FakeNm(), events)
        g.evaluator.baseline_servers = ["1.1.1.1", "9.9.9.9"]
        assert g.recommendations() == []
        assert g.status()["resolvers_lan_only"] is False

    def test_mixed_chain_no_guidance(self):
        assert is_lan_resolver("192.168.100.1") is True
        assert is_lan_resolver("1.1.1.1") is False
        assert is_lan_resolver("127.0.0.53") is False   # stub is loopback
        assert parse_resolv_conf("nameserver 1.1.1.1\n") == ["1.1.1.1"]
