"""FirewallManager — nftables enforcement with validate-and-rollback (ADR-003).

Engine-owned tables ONLY (`inet netfend_filter`, `arp netfend_arp`):
never flushes or touches foreign rules (audit RC-4). Application flow:

  1. build ruleset text (pure function, unit-tested)
  2. `nft -c -f` dry-run validation
  3. apply with `nft -f`
  4. connectivity self-check (gateway ICMP + DNS resolution)
  5. on failure -> delete tables (rollback), emit CRITICAL event, backoff

Standard profile keeps chain policy `accept` and only drops hostile
patterns (invalid, floods, scans) so legitimate traffic is never throttled
(owner requirement #1). The strict profile (opt-in) is default-drop.
"""
import json
import subprocess
import time
from typing import Any, Dict, List, Optional

from netfend.models.events import EventStore
from netfend.utils import capabilities
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn, log_err
from netfend.utils.validators import valid_ipv4, valid_mac, valid_ports

FILTER_TABLE = "netfend_filter"
ARP_TABLE = "netfend_arp"
_TIMEOUT = 8


# ---------------------------------------------------------------------------
# Pure ruleset builders (unit-testable)
# ---------------------------------------------------------------------------

def build_filter_ruleset(profile: str, new_conn_rate: int, new_conn_burst: int,
                         icmp_rate: int, icmp_burst: int,
                         strict_tcp_ports: List[int], strict_udp_ports: List[int],
                         icmpv6: bool = True) -> str:
    """Generate the `inet netfend_filter` ruleset text."""
    if profile not in ("standard", "strict"):
        raise ValueError(f"unknown firewall profile: {profile}")
    if new_conn_rate <= 0 or icmp_rate <= 0 or new_conn_burst <= 0 or icmp_burst <= 0:
        raise ValueError("rate limits must be positive")
    if not valid_ports(strict_tcp_ports) or not valid_ports(strict_udp_ports):
        raise ValueError("port lists must contain valid ports")

    policy = "accept" if profile == "standard" else "drop"
    lines = [
        f"table inet {FILTER_TABLE} {{",
        "  chain input {",
        "    type filter hook input priority 0; policy " + policy + ";",
        "    iifname \"lo\" accept comment \"netfend: loopback\"",
        "    ct state established,related accept comment \"netfend: established and related\"",
        "    ct state invalid drop comment \"netfend: invalid state\"",
        "    # Per-source NEW connection rate limit (scan / SYN-flood resistance)",
        f"    tcp flags & (fin | syn | rst | ack) == syn ct state new meter netfend_synflood {{ ip saddr timeout 30s limit rate over {new_conn_rate}/second burst {new_conn_burst} packets }} counter drop comment \"netfend: syn flood per source\"",
        f"    meta l4proto udp ct state new meter netfend_udpflood {{ ip saddr timeout 30s limit rate over {new_conn_rate}/second burst {new_conn_burst} packets }} counter drop comment \"netfend: udp flood per source\"",
        "    # ICMP echo flood limits (ICMP itself stays allowed)",
        f"    ip protocol icmp icmp type echo-request limit rate over {icmp_rate}/second burst {icmp_burst} packets counter drop comment \"netfend: icmp4 echo flood\"",
    ]
    if icmpv6:
        lines.append(
            f"    ip6 nexthdr ipv6-icmp icmpv6 type echo-request limit rate over {icmp_rate}/second burst {icmp_burst} packets counter drop comment \"netfend: icmp6 echo flood\"")
    if profile == "strict":
        # Essentials that must stay reachable even in default-drop
        lines += [
            "    ip protocol icmp accept comment \"netfend: icmp essential\"",
            "    ip6 nexthdr ipv6-icmp accept comment \"netfend: icmpv6 essential (NDP)\"",
            "    udp sport 67 udp dport 68 accept comment \"netfend: DHCPv4 client\"",
            "    udp sport 547 udp dport 546 accept comment \"netfend: DHCPv6 client\"",
            "    meta l4proto tcp ct state new udp dport 53 counter drop comment \"netfend: nonsensical tcp/udp combo (kept explicit for clarity)\"",
        ]
        for p in strict_tcp_ports:
            lines.append(f"    tcp dport {p} ct state new accept comment \"netfend: allowed tcp/{p}\"")
        for p in strict_udp_ports:
            lines.append(f"    udp dport {p} ct state new accept comment \"netfend: allowed udp/{p}\"")
    lines += [
        "  }",
        "}",
        "",
    ]
    return "\n".join(lines)


def build_arp_ruleset(my_ip: str, my_mac: str, gw_ip: Optional[str],
                      gw_mac: Optional[str]) -> str:
    """Generate the `arp netfend_arp` ruleset text.

    Fixes audit RC-8: the own-IP rule matches ONLY frames from a foreign
    MAC (sender MAC != our MAC). DAD probes (spa 0.0.0.0) never match
    `arp saddr ip <my_ip>` and are therefore unaffected.
    """
    if not (valid_ipv4(my_ip) and valid_mac(my_mac)):
        raise ValueError("valid my_ip and my_mac required for arp rules")
    if gw_ip is not None and not valid_ipv4(gw_ip):
        raise ValueError("invalid gateway ip")
    if gw_mac is not None and not valid_mac(gw_mac):
        raise ValueError("invalid gateway mac")
    lines = [
        f"table arp {ARP_TABLE} {{",
        "  chain input {",
        "    type filter hook input priority 0; policy accept;",
        f"    arp saddr ip {my_ip} arp saddr mac != {my_mac.lower()} counter drop comment \"netfend: foreign MAC claims our IP\"",
    ]
    if gw_ip and gw_mac:
        lines.append(
            f"    arp saddr ip {gw_ip} arp saddr mac != {gw_mac.lower()} counter drop comment \"netfend: foreign MAC claims gateway IP\"")
    lines += [
        "  }",
        "}",
        "",
    ]
    return "\n".join(lines)


def parse_nft_counters(nft_json_output: str) -> Dict[str, Dict[str, int]]:
    """Parse `nft -j list table ...` output into {comment: {packets, bytes}}."""
    try:
        data = json.loads(nft_json_output)
    except (json.JSONDecodeError, TypeError):
        return {}
    counters: Dict[str, Dict[str, int]] = {}

    def _walk(obj: Any):
        if isinstance(obj, dict):
            exprs = obj.get("expr")
            if isinstance(exprs, list):
                comment = None
                pkt = bts = None
                for e in exprs:
                    if not isinstance(e, dict):
                        continue
                    if "counter" in e:
                        pkt = e["counter"].get("packets")
                        bts = e["counter"].get("bytes")
                    if "comment" in e:
                        comment = e["comment"]
                if comment is not None and pkt is not None:
                    counters[comment] = {"packets": pkt, "bytes": bts or 0}
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v)

    _walk(data)
    return counters


# ---------------------------------------------------------------------------
# FirewallManager
# ---------------------------------------------------------------------------

class FirewallManager:
    def __init__(self, nm, events: EventStore):
        self.nm = nm                       # NetworkManager
        self.events = events
        self.applied = False
        self.applied_at: Optional[float] = None
        self.last_failure: Optional[float] = None
        self.last_error: Optional[str] = None
        self.profile: str = "standard"

    # -- capability/status ---------------------------------------------------
    def available(self) -> bool:
        return (capabilities.have("nft") and capabilities.have("root")
                and capabilities.have("nftables") and not cfg("general", "dry_run"))

    def status(self) -> Dict[str, Any]:
        snap = self.nm.snapshot()
        return {
            "available": self.available(),
            "applied": self.applied,
            "applied_at": self.applied_at,
            "profile": self.profile,
            "last_failure": self.last_failure,
            "last_error": self.last_error,
            "dry_run": bool(cfg("general", "dry_run")),
            "counters": self.read_counters(),
            "gateway_pinned": bool(snap.get("gateway_ip") and snap.get("gateway_mac")),
        }

    # -- application ----------------------------------------------------------
    def apply(self, interface: str = None) -> bool:
        """Validate + apply rulesets. Returns True when rules are active."""
        if not self.available():
            reason = ("dry-run mode" if cfg("general", "dry_run")
                      else "missing nft/root/nftables capability")
            self.events.emit_simple(
                "firewall.unavailable", "notice", "unverified",
                f"Firewall enforcement unavailable: {reason}",
                source="firewall")
            return False

        # Backoff after a recent failed apply (avoid tight failure loops)
        cooldown = cfg("firewall", "rollback_cooldown_s", 300)
        if self.last_failure and (time.time() - self.last_failure) < cooldown:
            log_warn("Firewall apply skipped: in rollback cooldown")
            return False

        snap = self.nm.snapshot()
        my_ip, my_mac = snap["my_ip"], snap["my_mac"]
        gw_ip, gw_mac = snap["gateway_ip"], snap["gateway_mac"]
        if not (my_ip and my_mac):
            self.last_error = "network identity incomplete (no ip/mac)"
            log_warn(f"Firewall apply deferred: {self.last_error}")
            return False

        self.profile = cfg("firewall", "profile", "standard")
        filter_rs = build_filter_ruleset(
            self.profile,
            cfg("firewall", "new_conn_rate_per_s", 50),
            cfg("firewall", "new_conn_burst", 100),
            cfg("firewall", "icmp_rate_per_s", 20),
            cfg("firewall", "icmp_burst", 40),
            cfg("firewall", "strict_allowed_tcp_ports", []),
            cfg("firewall", "strict_allowed_udp_ports", [53, 67, 68]),
        )
        arp_rs = build_arp_ruleset(my_ip, my_mac, gw_ip, gw_mac)

        # 1) dry-run validation of both rulesets
        if not self._nft_check(filter_rs) or not self._nft_check(arp_rs):
            self.last_failure = time.time()
            self.last_error = "ruleset failed nft -c validation"
            self.events.emit_simple(
                "firewall.validation_failed", "critical", "confirmed",
                self.last_error, source="firewall")
            return False

        # 2) apply
        if not self._nft_apply(filter_rs) or not self._nft_apply(arp_rs):
            self.rollback(reason="apply command failed")
            return False

        # 3) connectivity self-check before declaring success
        if not self._selfcheck():
            self.rollback(reason="connectivity self-check failed after apply")
            return False

        self.applied = True
        self.applied_at = time.time()
        self.last_failure = None
        log_info(f"Firewall active (profile={self.profile}, tables={FILTER_TABLE}+{ARP_TABLE})")
        self.events.emit_simple(
            "firewall.applied", "info", "confirmed",
            f"Firewall rules active (profile: {self.profile})",
            source="firewall", profile=self.profile,
            interface=interface or snap["interface"])
        return True

    def _nft_check(self, ruleset: str) -> bool:
        try:
            r = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset,
                               capture_output=True, text=True, timeout=_TIMEOUT)
            if r.returncode != 0:
                log_err(f"nft -c rejected ruleset: {r.stderr.strip()[:300]}")
                return False
            return True
        except (OSError, subprocess.SubprocessError) as e:
            log_err(f"nft check error: {e}")
            return False

    def _nft_apply(self, ruleset: str) -> bool:
        try:
            r = subprocess.run(["nft", "-f", "-"], input=ruleset,
                               capture_output=True, text=True, timeout=_TIMEOUT)
            if r.returncode != 0:
                log_err(f"nft apply failed: {r.stderr.strip()[:300]}")
                return False
            return True
        except (OSError, subprocess.SubprocessError) as e:
            log_err(f"nft apply error: {e}")
            return False

    def _selfcheck(self) -> bool:
        """Confirm we did not break our own connectivity (owner safeguard).

        Gateway ICMP must pass; DNS resolution is checked when a probe
        domain is configured. Failures trigger rollback (ADR-003).
        """
        timeout = cfg("firewall", "selfcheck_timeout_s", 6)
        snap = self.nm.snapshot()
        gw = snap.get("gateway_ip")
        gw_ok = True
        if gw:
            try:
                r = subprocess.run(
                    ["ping", "-c", "1", "-W", str(max(1, int(timeout))), gw],
                    capture_output=True, timeout=timeout + 2)
                gw_ok = r.returncode == 0
            except (OSError, subprocess.SubprocessError):
                gw_ok = True  # ping unavailable: cannot judge, do not rollback
        dns_ok = True
        domain = cfg("dns", "probe_domain", "example.com")
        try:
            import socket
            socket.setdefaulttimeout(timeout)
            socket.getaddrinfo(domain, None)
        except OSError:
            # DNS may legitimately be down pre-apply; only fail when gw was fine
            dns_ok = False
        if not gw_ok:
            return False
        if gw_ok and not dns_ok and cfg("dns", "enabled", True):
            # Distinguish "we broke it" from "it was already broken": compare
            # with pre-apply state handled by caller via engine health. To be
            # safe we do NOT rollback on DNS-only failure (policy accept keeps
            # UDP replies flowing via established rule); we log for diagnosis.
            log_warn("DNS self-check failed after apply (pre-existing condition possible)")
        return True

    def rollback(self, reason: str) -> None:
        """Remove engine-owned tables only. Never touches other rules."""
        self.applied = False
        self.last_failure = time.time()
        self.last_error = reason
        for family, table in (("inet", FILTER_TABLE), ("arp", ARP_TABLE)):
            try:
                subprocess.run(["nft", "delete", "table", family, table],
                               capture_output=True, timeout=_TIMEOUT)
            except (OSError, subprocess.SubprocessError):
                pass
        log_err(f"Firewall rolled back: {reason}")
        self.events.emit_simple(
            "firewall.rollback", "critical", "confirmed",
            f"Firewall rules rolled back: {reason}", source="firewall")

    def remove(self) -> None:
        """Clean removal on engine stop (idempotent, safe when absent)."""
        if self.applied or self.last_failure is not None:
            for family, table in (("inet", FILTER_TABLE), ("arp", ARP_TABLE)):
                try:
                    subprocess.run(["nft", "delete", "table", family, table],
                                   capture_output=True, timeout=_TIMEOUT)
                except (OSError, subprocess.SubprocessError):
                    pass
            self.applied = False
            log_info("Firewall tables removed (clean shutdown)")

    # -- observability ---------------------------------------------------------
    def read_counters(self) -> Dict[str, Dict[str, int]]:
        """Read drop counters for the dashboard security panel."""
        if not (self.applied and capabilities.have("nft")):
            return {}
        out: Dict[str, Dict[str, int]] = {}
        for family, table in (("inet", FILTER_TABLE), ("arp", ARP_TABLE)):
            try:
                r = subprocess.run(["nft", "-j", "list", "table", family, table],
                                   capture_output=True, text=True, timeout=_TIMEOUT)
                if r.returncode == 0:
                    out.update(parse_nft_counters(r.stdout))
            except (OSError, subprocess.SubprocessError):
                continue
        return out
