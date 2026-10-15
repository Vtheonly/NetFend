"""ThreatIntelligence — behavioral profiles + MAC-alias correlation.

Kept from the original (good design, audit §4): escalation ladder,
timing fingerprints that survive MAC changes, fingerprint-based alias
inheritance. Changed:
- saves are debounced (no disk write per attack event — audit RC-9)
- `summary()` for the dashboard (no printing inside the service)

P-29 — fuzzy MAC-rotation correlation: the exact-quantized fingerprint
hash only matches when mean/stddev quantize identically; a tiny cadence
drift or a different sample window breaks it. Dedicated attack suites
(bettercap, NetCut) rotate MACs while keeping their tool cadence and
technique set. `correlate()` therefore compares raw timing stats with
tolerance PLUS technique-set overlap / common spoofed targets, links
the profiles bidirectionally in a persisted `alias_map`, inherits the
highest threat level across the group, and surfaces the rotation as an
`intel.mac_rotation` event (dashboard-visible). Locally-administered
MACs (the only kind an attacker CAN rotate through) are flagged in the
profile notes and in `summary()` — a signal, never proof, since phone
privacy randomization sets the same bit.
"""
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from netfend.models.threat_profile import ThreatProfile
from netfend.utils.config import (
    BLACKLIST_FILE, THREAT_MONITOR, THREAT_HIERARCHY,
)
from netfend.utils.logging import log_info, log_warn, log_alert, log_escalation

_SAVE_DEBOUNCE_S = 10.0

# fuzzy-correlation tolerances (P-29)
_MEAN_REL_TOL = 0.35        # cadence similarity: relative mean difference
_TECHNIQUE_JACCARD = 0.5    # technique-set overlap (OR common target IP)
_MIN_INTERVALS = 5          # both profiles need this many burst intervals


def jaccard(a: Set[str], b: Set[str]) -> float:
    """Set overlap in [0, 1]; 1.0 for two empty sets (no information)."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class ThreatIntelligence:
    def __init__(self, path: Path = None, events=None):
        self.path = Path(path) if path else BLACKLIST_FILE
        self.events = events               # optional EventStore (P-29 events)
        self.profiles: Dict[str, ThreatProfile] = {}
        self.fingerprint_map: Dict[str, set] = {}
        self.alias_map: Dict[str, List[str]] = {}   # mac -> known aliases (P-29)
        self._lock = threading.Lock()
        self._last_save = 0.0
        self._dirty = False
        self._load()

    def _load(self):
        import json
        try:
            if self.path.exists():
                with open(self.path, "r") as f:
                    data = json.load(f)
                for entry in data.get("profiles", []):
                    p = ThreatProfile.from_dict(entry)
                    self.profiles[p.mac] = p
                self.fingerprint_map = {
                    k: set(v) for k, v in data.get("fingerprint_map", {}).items()
                }
                self.alias_map = {
                    k: list(v) for k, v in data.get("alias_map", {}).items()}
                log_info(f"Loaded {len(self.profiles)} threat profiles.")
        except (OSError, json.JSONDecodeError) as e:
            log_warn(f"Could not load blacklist: {e}")

    def save(self, force: bool = False) -> bool:
        now = time.time()
        with self._lock:
            if not force and now - self._last_save < _SAVE_DEBOUNCE_S:
                self._dirty = True
                return True
            self._last_save = now
            self._dirty = False
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                import json
                data = {
                    "profiles": [p.to_dict() for p in self.profiles.values()],
                    "fingerprint_map": {k: list(v) for k, v in self.fingerprint_map.items()},
                    "alias_map": self.alias_map,
                    "last_saved": datetime.now().isoformat(),
                }
                with open(self.path, "w") as f:
                    json.dump(data, f, indent=2)
                return True
            except OSError as e:
                log_warn(f"Could not save blacklist: {e}")
                return False

    def record_attack(self, mac: str, technique: str,
                      spoofed_ip: Optional[str] = None) -> ThreatProfile:
        mac = mac.lower()
        rotation_events: List[Dict[str, Any]] = []
        with self._lock:
            if mac not in self.profiles:
                profile = ThreatProfile(mac)
                self.profiles[mac] = profile
                log_alert(f"New attacker profile created: {mac}")
                if profile.is_locally_administered():
                    note = ("uses a locally-administered (randomized) MAC — "
                            "common for MAC-rotation attackers; also produced "
                            "by phone privacy randomization (signal, not proof)")
                    profile.notes.append(note)

            profile = self.profiles[mac]
            old_level = profile.threat_level
            escalated = profile.record_attack(technique, spoofed_ip)

            if escalated:
                log_escalation(mac, old_level, profile.threat_level)

            fp = profile.get_behavior_fingerprint()
            if fp:
                self.fingerprint_map.setdefault(fp, set()).add(mac)
                aliases = self.fingerprint_map[fp] - {mac}
                if aliases:
                    msg = f"MAC {mac} matches behavioral fingerprint of: {', '.join(sorted(aliases))}"
                    if msg not in profile.notes:
                        profile.notes.append(msg)
                    for alias_mac in aliases:
                        if alias_mac in self.profiles:
                            alias_lvl = self.profiles[alias_mac].threat_level
                            try:
                                alias_idx = THREAT_HIERARCHY.index(alias_lvl)
                                cur_idx = THREAT_HIERARCHY.index(profile.threat_level)
                                if alias_idx > cur_idx:
                                    profile.threat_level = alias_lvl
                                    log_escalation(
                                        mac, THREAT_HIERARCHY[cur_idx], alias_lvl,
                                        reason="inherited from fingerprint match")
                            except ValueError:
                                pass

            # P-29: fuzzy correlation across MAC-rotation schemes
            rotation_events = self._correlate_locked(profile)
        self.save()  # debounced
        for ev in rotation_events:
            self._emit_rotation(ev)
        return profile

    # -- fuzzy MAC-rotation correlation (P-29) --------------------------------
    def _correlate_locked(self, profile: ThreatProfile) -> List[Dict[str, Any]]:
        """Link `profile` to known attackers with similar tool cadence.

        Must be called while holding self._lock. A pair is correlated when
        BOTH have enough burst intervals, the cadence means are within
        _MEAN_REL_TOL relative difference, AND the technique sets overlap
        (Jaccard) or the profiles target the same spoofed IP. Links are
        bidirectional, persisted via alias_map, and inherit the highest
        threat level across the group.
        """
        events: List[Dict[str, Any]] = []
        stats = profile.timing_stats()
        if not stats:
            return events
        known_aliases = set(self.alias_map.get(profile.mac, []))

        for mac2, p2 in self.profiles.items():
            if mac2 == profile.mac or mac2 in known_aliases:
                continue
            stats2 = p2.timing_stats()
            if not stats2:
                continue
            mean_rel = abs(stats["mean"] - stats2["mean"]) / max(
                stats["mean"], stats2["mean"], 1e-9)
            if mean_rel > _MEAN_REL_TOL:
                continue
            overlap = jaccard(profile.techniques, p2.techniques)
            same_target = bool(profile.spoofed_ips & p2.spoofed_ips)
            if not (overlap >= _TECHNIQUE_JACCARD or same_target):
                continue

            # correlated — record the bidirectional link
            self._link_aliases(profile.mac, mac2)
            note = (f"MAC rotation: {profile.mac} and {mac2} share tool "
                    f"cadence (means {stats['mean']:.2f}s/{stats2['mean']:.2f}s) "
                    f"and attack profile — same operator likely")
            if note not in profile.notes:
                profile.notes.append(note)
            if note not in p2.notes:
                p2.notes.append(note)

            # inherit the highest level across the alias group
            try:
                their_idx = THREAT_HIERARCHY.index(p2.threat_level)
                our_idx = THREAT_HIERARCHY.index(profile.threat_level)
            except ValueError:
                continue
            inherited = None
            if their_idx > our_idx:
                profile.threat_level = p2.threat_level
                inherited = p2.threat_level
            elif our_idx > their_idx:
                p2.threat_level = profile.threat_level
                inherited = profile.threat_level

            events.append({
                "kind": "intel.mac_rotation",
                "mac": profile.mac,
                "alias": mac2,
                "mean_rel_diff": round(mean_rel, 3),
                "technique_jaccard": round(overlap, 3),
                "same_target": same_target,
                "inherited_level": inherited,
            })
        return events

    def _link_aliases(self, mac1: str, mac2: str) -> None:
        self.alias_map.setdefault(mac1, [])
        self.alias_map.setdefault(mac2, [])
        if mac2 not in self.alias_map[mac1]:
            self.alias_map[mac1].append(mac2)
        if mac1 not in self.alias_map[mac2]:
            self.alias_map[mac2].append(mac1)

    def _emit_rotation(self, ev: Dict[str, Any]) -> None:
        log_warn(f"[MAC ROTATION] {ev['mac']} correlates with known "
                 f"attacker {ev['alias']} (cadence match, techniques "
                 f"overlap {ev['technique_jaccard']})")
        if self.events is None:
            return
        try:
            self.events.emit_simple(
                "intel.mac_rotation", "warning", "suspected",
                f"New attacker MAC {ev['mac']} matches the tool cadence and "
                f"attack profile of known attacker {ev['alias']} — MAC "
                f"rotation likely; threat level inherited"
                + (f" ({ev['inherited_level']})" if ev.get("inherited_level") else ""),
                source="intel", **{k: v for k, v in ev.items()
                                   if k not in ("kind",)})
        except Exception:
            pass  # event emission must never break recording

    def correlate(self, mac: str) -> List[Dict[str, Any]]:
        """Public/testable entry: run fuzzy correlation for one MAC now."""
        mac = mac.lower()
        with self._lock:
            profile = self.profiles.get(mac)
            if profile is None:
                return []
            return self._correlate_locked(profile)

    def get_threat_level(self, mac: str) -> Optional[str]:
        """Effective (age-decayed) threat level — P-25."""
        mac = mac.lower()
        with self._lock:
            if mac in self.profiles:
                return self.profiles[mac].effective_level()
        return None

    def summary(self) -> List[Dict[str, Any]]:
        """Dashboard/CLI view of known hostile profiles.

        P-25: entries carry the age-decayed effective level plus a stale
        marker; active (recent) threats sort before historical ones so a
        months-old profile with a huge counter cannot dominate the panel.
        P-29: entries carry the randomized-MAC flag and known aliases.
        """
        from datetime import datetime as _dt
        now = _dt.now()
        with self._lock:
            entries = []
            for mac, p in self.profiles.items():
                stale_days = round(p.days_since_last_seen(now), 1)
                entries.append({
                    "mac": mac,
                    "threat_level": p.threat_level,
                    "effective_threat_level": p.effective_level(now),
                    "stale": p.is_stale(now),
                    "stale_days": stale_days,
                    "total_attacks": p.total_attacks,
                    "techniques": sorted(p.techniques),
                    "spoofed_ips": sorted(p.spoofed_ips),
                    "randomized_mac": p.is_locally_administered(),
                    "aliases": sorted(set(self.alias_map.get(mac, []))),
                    "first_seen": p.first_seen,
                    "last_seen": p.last_seen,
                    "notes": list(p.notes),
                })
            # active threats first (most recently seen first), then stale
            # ones (least-stale first); counters break ties — a months-old
            # profile cannot dominate the panel regardless of its counter
            entries.sort(key=lambda e: (e["stale"], e["stale_days"],
                                        -e["total_attacks"]))
            return entries

    def get_status_report(self) -> List[str]:
        """Legacy text report (kept for CLI compatibility)."""
        return [
            f"  {r['mac']}  | {r['effective_threat_level']:8s} | "
            f"{r['total_attacks']:4d} attacks | "
            f"techniques: {', '.join(r['techniques'])} | last: {r['last_seen']}"
            + (f" | STALE {r['stale_days']}d" if r["stale"] else "")
            + (f" | RANDOMIZED MAC" if r["randomized_mac"] else "")
            + (f" | aliases: {', '.join(r['aliases'])}" if r["aliases"] else "")
            for r in self.summary()
        ]

    def stop(self):
        if self._dirty:
            self.save(force=True)
