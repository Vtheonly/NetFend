"""FirewallManager — nftables enforcement with validate-and-rollback (ADR-003).

Engine-owned tables ONLY (`inet netfend_filter`, `arp netfend_arp`):
never flushes or touches foreign rules (audit RC-4).

Field-tested hardening (problem P-18, live report 2026-10-15):
The first deployment run showed `ruleset failed nft -c validation` leaving
the host with ZERO protection. Two design flaws caused that:

  1. All-or-nothing validation: when the *inet filter* ruleset was
     rejected (nft version incompatibility), the *arp* table — the one
     that matters most against NetCut-class gateway spoofing — was never
     even attempted.
  2. The failure event carried no nft stderr, so the actual reason was
     undiscoverable from the dashboard.

Application flow now:

  1. build candidate rulesets per table (pure functions, unit-tested)
  2. per table, INDEPENDENTLY: try candidates in order (full -> basic ->
     minimal) until one passes `nft -c`; the first candidate that
     validates is applied
  3. the ARP table is applied FIRST (critical path) and never blocked by
     filter-table failures
  4. connectivity self-check (gateway ICMP + DNS resolution)
  5. on failure -> delete engine-owned tables (rollback), CRITICAL event
     including the nft stderr excerpt, backoff

Field-tested round 2 (2026-10-16, live install report):
The second deployment showed `nft -c rejected ruleset` on every ARP
table attempt — the token was `arp saddr mac`, but nft's grammar for
the ARP payload is `arp saddr {ip|ether}` (hardware field = `ether`).
Three compounding design flaws turned one bad token into a total
kernel-layer outage (P-37..P-40):

  5. Both ARP candidates shared the bad token, so the whole ladder was
     rejected — and the early `return False` then skipped the filter
     table too (P-38: table independence only worked one way).
  6. The failure cooldown (300 s) then blocked every re-apply triggered
     by the gateway re-baselines — while the log claimed kernel drops
     were active (P-39: cooldown must gate identical retries, never
     identity changes).
  7. `nft -f` APPENDS rules to existing chains — re-applying over live
     tables (re-baseline, DHCP renew, crash leftovers) would stack
     duplicate rules and keep defending a stale gateway MAC (P-40:
     engine-owned tables are dropped first, then rebuilt).

Standard profile keeps chain policy `accept` and only drops hostile
patterns (invalid, floods, scans) so legitimate traffic is never throttled
(owner requirement #1). The strict profile (opt-in) is default-drop.
"""
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from netfend.models.events import EventStore
from netfend.utils import capabilities
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn, log_err
from netfend.utils.validators import valid_ipv4, valid_mac, valid_ports

FILTER_TABLE = "netfend_filter"
ARP_TABLE = "netfend_arp"
_TIMEOUT = 8

# How much nft stderr to surface in events/logs (keep events readable)
_ERR_EXCERPT = 200

# P-37: nft grammar for the ARP payload hardware (MAC) address field is
# `arp saddr ether` / `arp daddr ether` — `arp saddr {ip|ether}`. The
# `mac` spelling is rejected by nft's parser ("syntax error, unexpected
# string, expecting ether or ip" — live report 2026-10-16). It is kept
# ONLY as a last-ditch fallback candidate in case an exotic nft build
# parses it; every stock nft release tested wants `ether`.
ARP_LL_TOKENS = ("ether", "mac")


# ---------------------------------------------------------------------------
# Pure ruleset builders (unit-testable)
# ---------------------------------------------------------------------------

def build_filter_ruleset(profile: str, new_conn_rate: int, new_conn_burst: int,
                         icmp_rate: int, icmp_burst: int,
                         strict_tcp_ports: List[int], strict_udp_ports: List[int],
                         icmpv6: bool = True, ra_guard: bool = False) -> str:
    """Generate the full `inet netfend_filter` ruleset text (candidate #1).

    Uses meters (dynamic per-source sets) — the most capable variant, but
    also the one most likely to be rejected by old nft versions, which is
    why `build_basic_filter_ruleset` exists as fallback.

    L3-metadata attack drops (T-32 / ADR-008): ICMP redirects (v4+v6)
    are ALWAYS dropped here — they are the gateway-grade route-hijack
    vector and never legitimate for this client (sysctl also disables
    them; the nft drop is line-rate belt-and-braces). When `ra_guard`
    is true (engine decided the network is v4-only), ICMPv6 router
    advertisements are dropped too — the mitm6/rogue-RA takeover.
    """
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
        "    # L3-metadata attack drops (redirects never legitimate for a client)",
        "    ip protocol icmp icmp type redirect counter drop comment \"netfend: icmp redirect drop\"",
        "    ip6 nexthdr ipv6-icmp icmpv6 type nd-redirect counter drop comment \"netfend: icmpv6 redirect drop\"",
        "    # Per-source NEW connection rate limit (scan / SYN-flood resistance)",
        f"    tcp flags & (fin | syn | rst | ack) == syn ct state new meter netfend_synflood {{ ip saddr timeout 30s limit rate over {new_conn_rate}/second burst {new_conn_burst} packets }} counter drop comment \"netfend: syn flood per source\"",
        f"    meta l4proto udp ct state new meter netfend_udpflood {{ ip saddr timeout 30s limit rate over {new_conn_rate}/second burst {new_conn_burst} packets }} counter drop comment \"netfend: udp flood per source\"",
        "    # ICMP echo flood limits (ICMP itself stays allowed)",
        f"    ip protocol icmp icmp type echo-request limit rate over {icmp_rate}/second burst {icmp_burst} packets counter drop comment \"netfend: icmp4 echo flood\"",
    ]
    if icmpv6:
        lines.append(
            f"    ip6 nexthdr ipv6-icmp icmpv6 type echo-request limit rate over {icmp_rate}/second burst {icmp_burst} packets counter drop comment \"netfend: icmp6 echo flood\"")
    if ra_guard:
        lines.append(
            "    ip6 nexthdr ipv6-icmp icmpv6 type nd-router-advert counter drop comment \"netfend: rogue RA guard (mitm6)\"")
    if profile == "strict":
        # Essentials that must stay reachable even in default-drop
        lines += [
            "    ip protocol icmp accept comment \"netfend: icmp essential\"",
            "    ip6 nexthdr ipv6-icmp accept comment \"netfend: icmpv6 essential (NDP)\"",
            "    udp sport 67 udp dport 68 accept comment \"netfend: DHCPv4 client\"",
            "    udp sport 547 udp dport 546 accept comment \"netfend: DHCPv6 client\"",
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


def build_basic_filter_ruleset(profile: str, icmp_rate: int, icmp_burst: int,
                               icmpv6: bool = True, ra_guard: bool = False) -> str:
    """Candidate #2: no meters (per-source sets) — works on older nft.

    Global (not per-source) rate limits. Weaker against distributed floods
    but preserves the essential drops (invalid state, redirects, and the
    RA drop when the guard is active).
    """
    if profile not in ("standard", "strict"):
        raise ValueError(f"unknown firewall profile: {profile}")
    if icmp_rate <= 0 or icmp_burst <= 0:
        raise ValueError("rate limits must be positive")
    policy = "accept" if profile == "standard" else "drop"
    lines = [
        f"table inet {FILTER_TABLE} {{",
        "  chain input {",
        "    type filter hook input priority 0; policy " + policy + ";",
        "    iifname \"lo\" accept comment \"netfend: loopback\"",
        "    ct state established,related accept comment \"netfend: established and related\"",
        "    ct state invalid drop comment \"netfend: invalid state\"",
        "    # L3-metadata attack drops (kept in the compatibility variant)",
        "    ip protocol icmp icmp type redirect counter drop comment \"netfend: icmp redirect drop\"",
        "    ip6 nexthdr ipv6-icmp icmpv6 type nd-redirect counter drop comment \"netfend: icmpv6 redirect drop\"",
        "    # Global NEW-connection rate limit (compatibility fallback, no per-source sets)",
        "    ct state new limit rate over 200/second burst 400 packets counter drop comment \"netfend: conn flood\"",
        f"    ip protocol icmp icmp type echo-request limit rate over {icmp_rate}/second burst {icmp_burst} packets counter drop comment \"netfend: icmp4 echo flood\"",
    ]
    if ra_guard:
        lines.append(
            "    ip6 nexthdr ipv6-icmp icmpv6 type nd-router-advert counter drop comment \"netfend: rogue RA guard (mitm6)\"")
    if icmpv6:
        lines.append(
            f"    ip6 nexthdr ipv6-icmp icmpv6 type echo-request limit rate over {icmp_rate}/second burst {icmp_burst} packets counter drop comment \"netfend: icmp6 echo flood\"")
    lines += [
        "  }",
        "}",
        "",
    ]
    return "\n".join(lines)


def build_minimal_filter_ruleset(profile: str) -> str:
    """Candidate #3: connection-tracking hygiene only.

    Maximum compatibility — accepts everything except invalid-state
    packets. Used when even plain `limit` statements are rejected.
    """
    if profile not in ("standard", "strict"):
        raise ValueError(f"unknown firewall profile: {profile}")
    policy = "accept" if profile == "standard" else "drop"
    if profile == "strict":
        # A default-drop chain with nothing else would cut the host off;
        # minimal strict still allows loopback/established/ICMP/DHCP.
        return "\n".join([
            f"table inet {FILTER_TABLE} {{",
            "  chain input {",
            "    type filter hook input priority 0; policy drop;",
            "    iifname \"lo\" accept comment \"netfend: loopback\"",
            "    ct state established,related accept comment \"netfend: established and related\"",
            "    ip protocol icmp accept comment \"netfend: icmp essential\"",
            "    ip6 nexthdr ipv6-icmp accept comment \"netfend: icmpv6 essential (NDP)\"",
            "    udp sport 67 udp dport 68 accept comment \"netfend: DHCPv4 client\"",
            "  }",
            "}",
            "",
        ])
    return "\n".join([
        f"table inet {FILTER_TABLE} {{",
        "  chain input {",
        "    type filter hook input priority 0; policy accept;",
        "    iifname \"lo\" accept comment \"netfend: loopback\"",
        "    ct state established,related accept comment \"netfend: established and related\"",
        "    ct state invalid drop comment \"netfend: invalid state\"",
        "  }",
        "}",
        "",
    ])


def build_arp_ruleset(my_ip: str, my_mac: str, gw_ip: Optional[str],
                      gw_mac: Optional[str], ll_token: str = "ether") -> str:
    """Generate the full `arp netfend_arp` ruleset text (candidate #1).

    Fixes audit RC-8: the own-IP rule matches ONLY frames from a foreign
    MAC (sender MAC != our MAC). DAD probes (spa 0.0.0.0) never match
    `arp saddr ip <my_ip>` and are therefore unaffected.

    P-37: `ll_token` selects the ARP hardware-address field spelling.
    Default "ether" is the nft grammar (`arp saddr {ip|ether}`);
    "mac" is the legacy spelling kept as a fallback candidate only.
    """
    if ll_token not in ARP_LL_TOKENS:
        raise ValueError(f"unknown arp link-layer token: {ll_token!r}")
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
        f"    arp saddr ip {my_ip} arp saddr {ll_token} != {my_mac.lower()} counter drop comment \"netfend: foreign MAC claims our IP\"",
    ]
    if gw_ip and gw_mac:
        lines.append(
            f"    arp saddr ip {gw_ip} arp saddr {ll_token} != {gw_mac.lower()} counter drop comment \"netfend: foreign MAC claims gateway IP\"")
    lines += [
        "  }",
        "}",
        "",
    ]
    return "\n".join(lines)


def build_minimal_arp_ruleset(my_ip: str, my_mac: str,
                              ll_token: str = "ether") -> str:
    """ARP candidate #2: own-IP protection only (gateway unknown or the
    gateway-pin rule is rejected). Own-IP hijack is the NetCut 'cut the
    victim off' primitive, so this rule is the one that must survive.

    P-37: `ll_token` as in `build_arp_ruleset` ("ether" default, "mac"
    legacy fallback candidate)."""
    if ll_token not in ARP_LL_TOKENS:
        raise ValueError(f"unknown arp link-layer token: {ll_token!r}")
    if not (valid_ipv4(my_ip) and valid_mac(my_mac)):
        raise ValueError("valid my_ip and my_mac required for arp rules")
    return "\n".join([
        f"table arp {ARP_TABLE} {{",
        "  chain input {",
        "    type filter hook input priority 0; policy accept;",
        f"    arp saddr ip {my_ip} arp saddr {ll_token} != {my_mac.lower()} counter drop comment \"netfend: foreign MAC claims our IP\"",
        "  }",
        "}",
        "",
    ])


def parse_nft_counters(nft_json_output: str) -> Dict[str, Dict[str, int]]:
    """Parse `nft -j list table ...` output into {comment: {packets, bytes}}."""
    import json
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


def _clip_err(stderr: str) -> str:
    """One-line excerpt of nft stderr for events/logs."""
    text = " ".join((stderr or "").split())
    return text[:_ERR_EXCERPT] + ("..." if len(text) > _ERR_EXCERPT else "")


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
        # which ruleset variant is active per table (P-18 observability)
        self.filter_variant: Optional[str] = None   # full|basic|minimal
        self.arp_variant: Optional[str] = None      # full|full-legacy|minimal|minimal-legacy
        # P-39: identity of the ruleset that last failed — the cooldown
        # gates only retries of the SAME identity
        self._fail_fingerprint: Optional[Tuple[str, ...]] = None
        self._last_ra_guard: bool = False
        # IPs dropped as DHCP-override targets (P-33)
        self.override_drops: List[str] = []

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
            "filter_variant": self.filter_variant,
            "arp_variant": self.arp_variant,
            "last_failure": self.last_failure,
            "last_error": self.last_error,
            "dry_run": bool(cfg("general", "dry_run")),
            "counters": self.read_counters(),
            "gateway_pinned": bool(snap.get("gateway_ip") and snap.get("gateway_mac")),
        }

    # -- application ----------------------------------------------------------
    def apply(self, interface: str = None, ra_guard: bool = False) -> bool:
        """Validate + apply rulesets. Returns True when rules are active.

        Tables are applied INDEPENDENTLY (P-18) — in BOTH directions
        (P-38): a rejected filter ruleset never blocks the ARP table,
        and a rejected ARP table no longer cancels the filter table
        either; each table falls back to simpler candidates when the
        richer ones are rejected by the local nft.

        Idempotency (P-40): `nft -f` APPENDS rules to existing chains,
        so re-applying over live tables would stack duplicate rules and
        keep defending a stale gateway MAC. Engine-owned tables are
        dropped first and rebuilt, then dynamic override drops re-added.

        Failure cooldown (P-39): retries with an UNCHANGED network
        identity wait out `rollback_cooldown_s`; an identity change
        (new IP / gateway MAC — e.g. a legitimate router replacement)
        always re-applies immediately so we never defend a ghost.

        `ra_guard` (from Ipv6Guard, T-32) adds the ICMPv6 RA drop to the
        filter ruleset — active only when the engine determined the
        network is v4-only, so legitimate IPv6 is never broken.
        """
        if not self.available():
            reason = ("dry-run mode" if cfg("general", "dry_run")
                      else "missing nft/root/nftables capability")
            self.events.emit_simple(
                "firewall.unavailable", "notice", "unverified",
                f"Firewall enforcement unavailable: {reason}",
                source="firewall")
            return False

        snap = self.nm.snapshot()
        my_ip, my_mac = snap["my_ip"], snap["my_mac"]
        gw_ip, gw_mac = snap["gateway_ip"], snap["gateway_mac"]
        if not (my_ip and my_mac):
            self.last_error = "network identity incomplete (no ip/mac)"
            log_warn(f"Firewall apply deferred: {self.last_error}")
            return False

        self.profile = cfg("firewall", "profile", "standard")
        if self.profile == "off":
            log_info("Firewall profile is 'off' — no rules will be applied")
            return False

        # Backoff after a recent failed apply (avoid tight failure loops) —
        # but ONLY for retries of the same identity (P-39): a network
        # change must always rebuild, or stale pins defend a ghost.
        cooldown = cfg("firewall", "rollback_cooldown_s", 300)
        if (self.last_failure is not None
                and (time.time() - self.last_failure) < cooldown
                and self._fail_fingerprint == self._fingerprint(snap, ra_guard)):
            log_warn("Firewall apply skipped: in rollback cooldown "
                     "(network identity unchanged since the failure)")
            return False

        self._last_ra_guard = bool(ra_guard)

        # P-40: rebuild from a clean slate — append semantics would
        # otherwise stack duplicate rules across re-baselines (and keep
        # stale pins from a crashed previous run alive).
        self._delete_owned_tables()
        self.applied = False
        self.filter_variant = None
        self.arp_variant = None

        # ------------------------------------------------------------------
        # 1) ARP table FIRST — the critical protection against gateway
        #    spoofing. Independent of the filter table (P-18). The
        #    hardware-address token ladder covers nft grammar drift (P-37).
        # ------------------------------------------------------------------
        arp_candidates: List[Tuple[str, str]] = []
        if gw_ip and gw_mac:
            arp_candidates.append(("full", build_arp_ruleset(
                my_ip, my_mac, gw_ip, gw_mac, "ether")))
            arp_candidates.append(("full-legacy", build_arp_ruleset(
                my_ip, my_mac, gw_ip, gw_mac, "mac")))
        arp_candidates.append(("minimal", build_minimal_arp_ruleset(
            my_ip, my_mac, "ether")))
        arp_candidates.append(("minimal-legacy", build_minimal_arp_ruleset(
            my_ip, my_mac, "mac")))
        arp_ok, arp_err = self._apply_first_valid(arp_candidates, "arp")
        if not arp_ok:
            # P-38: no early return — the filter table still provides
            # invalid/flood/redirect/RA drops and must be attempted.
            self.last_error = f"arp table rejected by nft: {arp_err}"
            self.events.emit_simple(
                "firewall.validation_failed", "critical", "confirmed",
                f"ARP firewall ruleset rejected by nft (no ARP anti-spoofing active): {arp_err}",
                source="firewall", table="arp", nft_error=arp_err)
        elif arp_err:
            # fell back to a weaker variant — surface it
            self.events.emit_simple(
                "firewall.fallback", "warning", "confirmed",
                f"Full ARP ruleset rejected, using fallback (variant: {self.arp_variant}): {arp_err}",
                source="firewall", table="arp", variant=self.arp_variant,
                nft_error=arp_err)

        # ------------------------------------------------------------------
        # 2) Filter table — independent BOTH ways (P-38): failure here
        #    degrades flood protection but never removes the ARP table,
        #    and ARP failure never cancels it either.
        # ------------------------------------------------------------------
        filter_candidates = [
            ("full", build_filter_ruleset(
                self.profile,
                cfg("firewall", "new_conn_rate_per_s", 50),
                cfg("firewall", "new_conn_burst", 100),
                cfg("firewall", "icmp_rate_per_s", 20),
                cfg("firewall", "icmp_burst", 40),
                cfg("firewall", "strict_allowed_tcp_ports", []),
                cfg("firewall", "strict_allowed_udp_ports", [53, 67, 68]),
                ra_guard=ra_guard)),
            ("basic", build_basic_filter_ruleset(
                self.profile,
                cfg("firewall", "icmp_rate_per_s", 20),
                cfg("firewall", "icmp_burst", 40),
                ra_guard=ra_guard)),
            ("minimal", build_minimal_filter_ruleset(self.profile)),
        ]
        filter_ok, filter_err = self._apply_first_valid(filter_candidates, "filter")
        if not filter_ok:
            self.last_error = f"filter table rejected by nft: {filter_err}"
            self.events.emit_simple(
                "firewall.validation_failed", "critical", "confirmed",
                (f"Filter ruleset rejected by nft (flood protection inactive; "
                 f"{'ARP protection IS active' if arp_ok else 'ARP protection ALSO inactive'}): "
                 f"{filter_err}"),
                source="firewall", table="inet", nft_error=filter_err)
            # ARP protection stays — do not roll it back (P-18)
        elif filter_err:
            self.events.emit_simple(
                "firewall.fallback", "warning", "confirmed",
                f"Full filter ruleset rejected, using fallback (variant: {self.filter_variant}): {filter_err}",
                source="firewall", table="inet", variant=self.filter_variant,
                nft_error=filter_err)

        if not (arp_ok or filter_ok):
            self.last_failure = time.time()
            self._fail_fingerprint = self._fingerprint(snap, ra_guard)
            return False

        # ------------------------------------------------------------------
        # 3) connectivity self-check before declaring success
        # ------------------------------------------------------------------
        if not self._selfcheck():
            self.rollback(reason="connectivity self-check failed after apply")
            return False

        self.applied = True
        self.applied_at = time.time()
        if arp_ok and filter_ok:
            self.last_failure = None
            self._fail_fingerprint = None
        else:
            # partial protection: keep a cooldown for the failed table so
            # identical retries back off, while identity changes re-apply
            self.last_failure = time.time()
            self._fail_fingerprint = self._fingerprint(snap, ra_guard)
        if not arp_ok:
            log_warn("Firewall active WITHOUT ARP anti-spoofing "
                     "(arp table rejected by nft) — see firewall.validation_failed")
        log_info(f"Firewall active (profile={self.profile}, "
                 f"filter={self.filter_variant}, arp={self.arp_variant})")
        self.events.emit_simple(
            "firewall.applied", "info", "confirmed",
            f"Firewall rules active (profile: {self.profile}, "
            f"filter: {self.filter_variant}, arp: {self.arp_variant})",
            source="firewall", profile=self.profile,
            filter_variant=self.filter_variant, arp_variant=self.arp_variant,
            interface=interface or snap["interface"])

        # P-40: re-add dynamic DHCP override drops lost with the rebuild
        if self.override_drops:
            dropped = list(self.override_drops)
            self.override_drops.clear()
            for ip in dropped:
                self.add_override_drop(ip)
        return True

    def _fingerprint(self, snap: Dict[str, Any], ra_guard: bool) -> Tuple[str, ...]:
        """Identity of the ruleset we would build (P-39 cooldown key)."""
        return (snap.get("my_ip"), snap.get("my_mac"),
                snap.get("gateway_ip"), snap.get("gateway_mac"),
                self.profile, bool(ra_guard))

    def _delete_owned_tables(self) -> None:
        """Remove engine-owned tables (idempotent; P-40 re-apply hygiene).

        Also cleans tables a crashed previous run may have left behind —
        `nft delete` on a missing table just errors, which we ignore.
        """
        for family, table in (("inet", FILTER_TABLE), ("arp", ARP_TABLE)):
            try:
                subprocess.run(["nft", "delete", "table", family, table],
                               capture_output=True, timeout=_TIMEOUT)
            except (OSError, subprocess.SubprocessError):
                pass

    def _apply_first_valid(self, candidates: List[Tuple[str, str]],
                           table: str) -> Tuple[bool, Optional[str]]:
        """Try candidate rulesets in order; apply the first that validates.

        `table` is "filter" or "arp" (selects which variant attribute is
        recorded). Returns (applied, first_rejected_error). The error
        belongs to the FULL variant (candidates[0]) when a fallback was
        used, so events still explain why the best variant was not possible.
        """
        first_err: Optional[str] = None
        for variant, ruleset in candidates:
            ok, err = self._nft_check(ruleset)
            if ok:
                applied, apply_err = self._nft_apply(ruleset)
                if applied:
                    if table == "filter":
                        self.filter_variant = variant
                    else:
                        self.arp_variant = variant
                    return True, first_err
                # check passed but apply failed — try next candidate
                if first_err is None:
                    first_err = f"apply failed: {_clip_err(apply_err or 'unknown')}"
                continue
            if first_err is None:
                first_err = _clip_err(err or "unknown error")
        return False, first_err

    def _nft_check(self, ruleset: str) -> Tuple[bool, Optional[str]]:
        """Dry-run validation. Returns (ok, stderr_excerpt)."""
        try:
            r = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset,
                               capture_output=True, text=True, timeout=_TIMEOUT)
            if r.returncode != 0:
                err = _clip_err(r.stderr)
                log_err(f"nft -c rejected ruleset: {err}")
                return False, err
            return True, None
        except (OSError, subprocess.SubprocessError) as e:
            log_err(f"nft check error: {e}")
            return False, str(e)

    def _nft_apply(self, ruleset: str) -> Tuple[bool, Optional[str]]:
        try:
            r = subprocess.run(["nft", "-f", "-"], input=ruleset,
                               capture_output=True, text=True, timeout=_TIMEOUT)
            if r.returncode != 0:
                err = _clip_err(r.stderr)
                log_err(f"nft apply failed: {err}")
                return False, err
            return True, None
        except (OSError, subprocess.SubprocessError) as e:
            log_err(f"nft apply error: {e}")
            return False, str(e)

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
        if not gw_ok:
            return False
        # DNS: pre-existing outages must not trigger rollback (the engine
        # may be applying rules right during a Wi-Fi reconnect). We log a
        # warning for diagnosis but only gateway reachability is decisive.
        try:
            import socket
            domain = cfg("dns", "probe_domain", "example.com")
            socket.setdefaulttimeout(timeout)
            try:
                socket.getaddrinfo(domain, None)
            except OSError:
                log_warn("DNS self-check failed after apply "
                         "(pre-existing condition possible)")
        except Exception:
            pass
        return True

    def rollback(self, reason: str) -> None:
        """Remove engine-owned tables only. Never touches other rules."""
        self.applied = False
        self.last_failure = time.time()
        self.last_error = reason
        self._fail_fingerprint = self._fingerprint(
            self.nm.snapshot(), self._last_ra_guard)
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
        """Clean removal on engine stop (idempotent, safe when absent).

        Unconditional (P-40): tables a crashed previous run left behind
        are cleaned too — deleting a missing table is a harmless no-op
        here, and leftovers would otherwise stack with the next apply.
        """
        self._delete_owned_tables()
        self.applied = False
        self.filter_variant = None
        self.arp_variant = None
        self.override_drops.clear()
        log_info("Firewall tables removed (clean shutdown)")

    # -- dynamic override drops (P-33) ------------------------------------------
    def add_override_drop(self, ip: str) -> bool:
        """Drop all traffic to/from a DHCP-override target at line rate.

        Called by the engine when a `dhcp.router_override` (critical,
        confirmed) names a router option that is NOT the verified
        gateway: the address is an attacker-controlled steering target,
        and traffic must never flow through it. Rules live in our own
        tables (ADR-003) and vanish with the table on engine stop.
        Idempotent per IP.
        """
        if not valid_ipv4(ip):
            log_warn(f"refusing override drop for invalid IP {ip!r}")
            return False
        if ip in self.override_drops:
            return True
        if not (self.applied and capabilities.have("nft")):
            log_warn(f"cannot add override drop for {ip}: filter table not active")
            return False
        cmds = [
            # ensure an output chain exists (input chain exists from apply)
            ["nft", "add", "chain", "inet", FILTER_TABLE, "output",
             "{ type filter hook output priority 0; policy accept; }"],
            ["nft", "add", "rule", "inet", FILTER_TABLE, "input",
             "ip", "saddr", ip, "counter", "drop",
             "comment", "netfend: DHCP override source"],
            ["nft", "add", "rule", "inet", FILTER_TABLE, "output",
             "ip", "daddr", ip, "counter", "drop",
             "comment", "netfend: DHCP override target"],
        ]
        for cmd in cmds:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=_TIMEOUT)
                # 'add chain' fails with EEXIST once the chain is there —
                # that specific failure is expected and fine
                if r.returncode != 0 and "File exists" not in (r.stderr or ""):
                    log_err(f"override drop rejected: {_clip_err(r.stderr)}")
                    return False
            except (OSError, subprocess.SubprocessError) as e:
                log_err(f"override drop error: {e}")
                return False
        self.override_drops.append(ip)
        log_info(f"DHCP override target {ip} now dropped at line rate")
        return True

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
