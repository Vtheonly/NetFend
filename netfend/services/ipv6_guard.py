"""Ipv6Guard — rogue RA / mitm6 vector suppression and detection (ADR-008).

The attack (mitm6, rogue SLAAC): Linux attackers exploit IPv6 when IPv4
ARP is defended. The attacker spams Router Advertisements (or answers
solicitations) so its link-local address becomes the victim's IPv6
default gateway, then wins DHCPv6 and DNS — traffic flows through the
attacker while IPv4 defenses watch a different protocol.

Defense split by network reality:

- **Suppression** (`ipv6.ra_guard`): on a v4-only LAN (the common home
  case — no IPv6 default route) the SAFE and COMPLETE counter is
  `accept_ra = 0` (kernel ignores all RAs) plus an nftables drop of
  ICMPv6 router advertisements (line-rate, belt-and-braces). We lose
  nothing: there is no legitimate IPv6 to break.
- **Detection** (`detect_ra_conflicts`): when the LAN DOES use IPv6,
  suppressing RAs would cut our own connectivity — instead the guard
  watches RA sources and flags more than one distinct router source in
  the window (`ipv6.ra_conflict`, the mitm6/rogue-RA signature).

The nftables RA drop lives in the firewall ruleset (built with
`ra_guard=True` by the engine when suppression is active); AF_PACKET
sniffers still see dropped frames, so detection keeps working even
while suppressing. accept_ra enforcement reuses the KernelHardener
save/restore/crash-recovery contract (ADR-007) with its own state file
(`ipv6_state.json`) so each module restores exactly what it changed.

Deliberately NOT claimed (AGENTS.md rule: never claim capability the
hardware/position cannot provide): DHCPv6 rogue-server *content*
inspection — the RA conflict detection covers the mitm6 routing
takeover; full DHCPv6 option analysis is documented as a future
extension in unknowns.
"""
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

from netfend.models.events import EventStore
from netfend.services.hardening import KernelHardener
from netfend.utils import capabilities
from netfend.utils.config import cfg, DATA_DIR
from netfend.utils.logging import log_info, log_warn


def should_enable_ra_guard(v6_default_route_present: Optional[bool],
                           mode: str) -> bool:
    """Pure decision: suppress RAs or not?

    mode "auto": guard only when no IPv6 default route exists (v4-only
    LAN — suppression is lossless). Unknown routing state (None) never
    suppresses (fail-open for connectivity, AGENTS.md rule 7).
    mode "on" / "off": explicit user decision.
    """
    if mode == "on":
        return True
    if mode == "off":
        return False
    if v6_default_route_present is None:
        return False
    return not v6_default_route_present


class RaEvaluator:
    """Pure state machine: distinct RA source tracking + conflict events."""

    def __init__(self, max_sources: int = 1, window: float = 60.0,
                 cooldown: float = 300.0):
        self.max_sources = max(1, int(max_sources))
        self.window = window
        self.cooldown = cooldown
        self._sources: Dict[str, float] = {}   # link-local -> last seen ts
        self._last_emit: Optional[float] = None  # None = never emitted

    def evaluate(self, src: str, now: float) -> List[Dict[str, Any]]:
        self._sources[src] = now
        active = {s: t for s, t in self._sources.items()
                  if now - t <= self.window}
        self._sources = active
        if len(active) > self.max_sources and (
                self._last_emit is None
                or now - self._last_emit >= self.cooldown):
            self._last_emit = now
            return [{
                "kind": "ipv6.ra_conflict",
                "severity": "critical",
                "confidence": "suspected",
                "summary": (f"{len(active)} distinct IPv6 router sources "
                            f"advertising ({', '.join(sorted(active))}) — "
                            f"rogue RA / mitm6 signature"),
                "evidence": {"sources": sorted(active),
                             "window_s": self.window,
                             "max_sources": self.max_sources}}]
        return []

    def sources(self) -> List[str]:
        return sorted(self._sources)


class Ipv6Guard:
    """Decision + enforcement + detection adapter for the mitm6 vector."""

    def __init__(self, nm, events: EventStore, intel=None,
                 proc_base: str = "/proc/sys"):
        self.nm = nm
        self.events = events
        self.intel = intel
        self.proc_base = proc_base
        self.evaluator = RaEvaluator(
            max_sources=int(cfg("ipv6", "ra_conflict_max_sources", 1)),
            window=float(cfg("ipv6", "ra_conflict_window_s", 60)),
            cooldown=float(cfg("ipv6", "ra_conflict_cooldown_s", 300)))
        self.guard_active: Optional[bool] = None   # decided at enforce time
        self._ra_hardener: Optional[KernelHardener] = None
        self._sniffer = None
        self._stop = threading.Event()

    # -- state file ------------------------------------------------------------
    def _state_path(self) -> Path:
        return Path(DATA_DIR) / "ipv6_state.json"

    def _make_hardener(self, iface: Optional[str]) -> KernelHardener:
        params = [
            ("net/ipv6/conf/all/accept_ra", "0"),
            ("net/ipv6/conf/default/accept_ra", "0"),
        ]
        if iface:
            params.append((f"net/ipv6/conf/{iface}/accept_ra", "0"))
        return KernelHardener(
            self.events, proc_base=self.proc_base,
            state_path=self._state_path(), params=params,
            event_prefix="ipv6.ra_guard",
            enabled_gate=lambda: bool(cfg("ipv6", "enabled", True)),
            describe="IPv6 RA guard (accept_ra=0 — mitm6 vector closed)")

    # -- decision + enforcement ---------------------------------------------------
    def evaluate_and_enforce(self) -> bool:
        """Decide whether RA suppression applies on this network and
        enforce it. Returns True when suppression is active (the engine
        then builds the firewall ruleset with the RA drop)."""
        try:
            if not cfg("ipv6", "enabled", True):
                self.guard_active = False
                return False

            mode = str(cfg("ipv6", "ra_guard", "auto"))
            if mode not in ("auto", "on", "off"):
                log_warn(f"unknown ipv6.ra_guard mode {mode!r}; using 'auto'")
                mode = "auto"

            v6_route = self.nm.has_ipv6_default_route()
            decision = should_enable_ra_guard(v6_route, mode)
            self.guard_active = decision

            if mode == "auto" and v6_route is None:
                self.events.emit_simple(
                    "ipv6.ra_guard_unknown", "notice", "unverified",
                    "Could not determine IPv6 routing (ip -6 route "
                    "unavailable); RA guard not enforced to avoid breaking "
                    "a possible IPv6 uplink. Set ipv6.ra_guard=on to force "
                    "suppression on a known v4-only network.",
                    source="ipv6")
            elif decision:
                self._ra_hardener = self._make_hardener(self.nm.interface)
                self._ra_hardener.apply()
                self.events.emit_simple(
                    "ipv6.ra_guard_active", "notice", "confirmed",
                    f"IPv6 RA guard active (accept_ra=0 + nft RA drop): no "
                    f"IPv6 default route detected on a '{mode}' network — "
                    f"rogue RA / mitm6 takeover closed",
                    source="ipv6", mode=mode,
                    v6_default_route=v6_route)
            elif v6_route:
                self.events.emit_simple(
                    "ipv6.ra_guard_inactive", "notice", "confirmed",
                    "IPv6 default route present — RA suppression NOT applied "
                    "(it would cut connectivity); monitoring RA sources for "
                    "conflicts instead",
                    source="ipv6", mode=mode)
            return decision
        except Exception as e:
            log_warn(f"IPv6 guard evaluate/enforce error: {e}")
            self.guard_active = False
            return False

    # -- RA conflict detection (scapy adapter) ---------------------------------
    def available(self) -> bool:
        return capabilities.have("scapy") and capabilities.have("root")

    def start(self) -> bool:
        if not cfg("ipv6", "enabled", True):
            return False
        if not cfg("ipv6", "detect_ra_conflicts", True):
            return False
        if not self.available():
            self.events.emit_simple(
                "ipv6.unavailable", "notice", "unverified",
                "IPv6 RA conflict detection unavailable (need scapy + root); "
                "suppression (when active) is unaffected",
                source="ipv6")
            return False
        snap = self.nm.snapshot()
        try:
            from scapy.all import AsyncSniffer
            # AF_PACKET taps see frames before netfilter input drops, so
            # detection works even while the nft RA drop is active.
            self._sniffer = AsyncSniffer(
                filter="icmp6", prn=self._on_packet, store=False,
                iface=snap["interface"])
            self._sniffer.start()
            log_info("IPv6 RA conflict detection sniffer active")
            return True
        except Exception as e:
            self.events.emit_simple(
                "ipv6.sniffer_failed", "warning", "unverified",
                f"IPv6 RA sniffer could not start: {e}",
                source="ipv6")
            return False

    def _on_packet(self, packet):
        try:
            from scapy.all import ICMPv6ND_RA, IPv6, Ether
            if not packet.haslayer(ICMPv6ND_RA):
                return
            src = packet[IPv6].src if packet.haslayer(IPv6) else None
            if not src:
                return
            for ev in self.evaluator.evaluate(src, time.time()):
                self.events.emit_simple(
                    ev["kind"], ev["severity"], ev["confidence"],
                    ev["summary"], source="ipv6", **ev.get("evidence", {}))
                if self.intel and packet.haslayer(Ether):
                    mac = (packet[Ether].src or "").lower()
                    if mac:
                        self.intel.record_attack(mac, "ipv6.ra_conflict", src)
        except Exception:
            pass  # a malformed packet must never kill the sniffer thread

    # -- lifecycle -----------------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        # restore accept_ra originals (also handles crash leftovers: a
        # fresh hardener with the same state file restores and clears it)
        if self._ra_hardener is not None:
            self._ra_hardener.restore()
        else:
            self._make_hardener(None).restore()

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": bool(cfg("ipv6", "enabled", True)),
            "mode": str(cfg("ipv6", "ra_guard", "auto")),
            "guard_active": self.guard_active,
            "suppression": "accept_ra=0 + nft RA drop"
                           if self.guard_active else
                           ("monitoring RA sources (IPv6 in use)"
                            if self.guard_active is False else "not evaluated"),
            "ra_sources_seen": self.evaluator.sources(),
            "detection_available": self.available(),
        }
