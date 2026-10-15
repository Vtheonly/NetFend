import math
import hashlib
from datetime import datetime, timedelta
from typing import List, Set, Dict, Any, Optional
from netfend.utils.config import THREAT_MONITOR, THREAT_HIERARCHY, ESCALATION_RULES

# Aging tiers (P-25): inactivity decays the DISPLAYED and DECISION level.
# Stored history is never rewritten — an attacker returning simply
# re-escalates through fresh attacks.
STALE_DAYS = 14          # one level down
VERY_STALE_DAYS = 30     # two levels down
ANCIENT_DAYS = 60        # down to MONITOR


class ThreatProfile:
    """Tracks behavioral data for a single attacker identity."""

    def __init__(self, mac: str, first_seen: Optional[str] = None):
        self.mac = mac.lower()
        self.threat_level = THREAT_MONITOR
        self.first_seen = first_seen or datetime.now().isoformat()
        self.last_seen = datetime.now().isoformat()
        self.attack_timestamps: List[str] = []          # ISO timestamps of each attack event
        self.techniques: Set[str] = set()               # e.g. "gateway_spoof", "identity_spoof"
        self.spoofed_ips: Set[str] = set()              # IPs this MAC has tried to impersonate
        self.burst_intervals: List[float] = []          # Time deltas between consecutive attacks (fingerprint)
        self.total_attacks = 0
        self.notes: List[str] = []

    # -- aging (P-25) -----------------------------------------------------------
    def days_since_last_seen(self, now: Optional[datetime] = None) -> float:
        try:
            last = datetime.fromisoformat(self.last_seen)
            return max(0.0, ((now or datetime.now()) - last).total_seconds() / 86400.0)
        except (ValueError, TypeError):
            return 0.0

    def effective_level(self, now: Optional[datetime] = None) -> str:
        """Stored threat level decayed by inactivity.

        Live-fire context (report.md 2026-10-15): a profile from June with
        63k recorded 'attacks' still displayed CRITICAL in October and
        dominated the dashboard. A stale attacker is history, not an
        active threat: 14 d silent -> one level down, 30 d -> two, 60 d ->
        MONITOR. Fresh activity immediately restores the stored level.
        """
        try:
            idx = THREAT_HIERARCHY.index(self.threat_level)
        except ValueError:
            return THREAT_MONITOR
        days = self.days_since_last_seen(now)
        if days >= ANCIENT_DAYS:
            decay = 3
        elif days >= VERY_STALE_DAYS:
            decay = 2
        elif days >= STALE_DAYS:
            decay = 1
        else:
            decay = 0
        return THREAT_HIERARCHY[max(0, idx - decay)]

    def is_stale(self, now: Optional[datetime] = None) -> bool:
        return self.days_since_last_seen(now) >= STALE_DAYS

    def record_attack(self, technique: str, spoofed_ip: Optional[str] = None) -> bool:
        """Records an attack event and returns True if threat level escalated."""
        now = datetime.now()
        self.last_seen = now.isoformat()
        self.total_attacks += 1
        self.techniques.add(technique)
        if spoofed_ip:
            self.spoofed_ips.add(spoofed_ip)

        # Record burst interval for fingerprinting
        if self.attack_timestamps:
            try:
                last = datetime.fromisoformat(self.attack_timestamps[-1])
                delta = (now - last).total_seconds()
                self.burst_intervals.append(round(delta, 4))
                # Keep only last 100 intervals
                self.burst_intervals = self.burst_intervals[-100:]
            except Exception:
                pass

        self.attack_timestamps.append(now.isoformat())
        # Keep only last 500 timestamps
        self.attack_timestamps = self.attack_timestamps[-500:]

        return self._evaluate_escalation()

    def _evaluate_escalation(self) -> bool:
        """Check if we should escalate the threat level. Returns True if level changed."""
        try:
            idx = THREAT_HIERARCHY.index(self.threat_level)
        except ValueError:
            idx = 0
            self.threat_level = THREAT_MONITOR

        if idx >= len(THREAT_HIERARCHY) - 1:
            return False  # Already at max

        rule = ESCALATION_RULES[self.threat_level]
        window = rule["window_secs"]
        threshold = rule["attacks_to_next"]

        try:
            cutoff = datetime.now() - timedelta(seconds=window)
            recent = []
            for t in self.attack_timestamps:
                try:
                    if datetime.fromisoformat(t) > cutoff:
                        recent.append(t)
                except ValueError:
                    continue
        except Exception:
            return False

        if len(recent) >= threshold:
            self.threat_level = THREAT_HIERARCHY[idx + 1]
            return True
        return False

    def get_behavior_fingerprint(self) -> Optional[str]:
        """
        Generate a behavioral fingerprint based on attack timing patterns.
        Even if the attacker changes their MAC, their tool's timing signature
        remains consistent. This allows us to correlate new MACs to known attackers.
        """
        if len(self.burst_intervals) < 5:
            return None

        intervals = self.burst_intervals[-50:]
        mean = sum(intervals) / len(intervals)
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        stddev = math.sqrt(variance) if variance > 0 else 0.0

        # Quantize to reduce noise
        q_mean = round(mean, 2)
        q_std = round(stddev, 2)
        techniques_str = ",".join(sorted(self.techniques))

        fingerprint_str = f"{q_mean}:{q_std}:{techniques_str}"
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mac": self.mac,
            "threat_level": self.threat_level,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "total_attacks": self.total_attacks,
            "techniques": list(self.techniques),
            "spoofed_ips": list(self.spoofed_ips),
            "burst_intervals": self.burst_intervals[-50:],
            "attack_timestamps": self.attack_timestamps[-50:],
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ThreatProfile":
        p = cls(d["mac"], d.get("first_seen"))
        p.threat_level = d.get("threat_level", THREAT_MONITOR)
        p.last_seen = d.get("last_seen", p.first_seen)
        p.total_attacks = d.get("total_attacks", 0)
        p.techniques = set(d.get("techniques", []))
        p.spoofed_ips = set(d.get("spoofed_ips", []))
        p.burst_intervals = d.get("burst_intervals", [])
        p.attack_timestamps = d.get("attack_timestamps", [])
        p.notes = d.get("notes", [])
        return p
