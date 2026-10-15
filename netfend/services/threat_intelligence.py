import json
import threading
from typing import Dict, Set, List, Optional, Any
from netfend.utils.config import DATA_DIR, BLACKLIST_FILE, THREAT_MONITOR, THREAT_HIERARCHY, COUNTERMEASURE_PROFILE
from netfend.utils.logging import log_info, log_warn, log_alert, log_escalation
from netfend.models.threat_profile import ThreatProfile

class ThreatIntelligence:
    """Manages the dynamic blacklist and behavioral fingerprinting database."""

    def __init__(self):
        self.profiles: Dict[str, ThreatProfile] = {}          # MAC → ThreatProfile
        self.fingerprint_map: Dict[str, Set[str]] = {}       # fingerprint_hash → set of MACs
        self._lock = threading.Lock()
        self._load()

    def _ensure_dir(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)

    def _load(self):
        self._ensure_dir()
        if BLACKLIST_FILE.exists():
            try:
                with open(BLACKLIST_FILE, "r") as f:
                    data = json.load(f)
                for entry in data.get("profiles", []):
                    p = ThreatProfile.from_dict(entry)
                    self.profiles[p.mac] = p
                self.fingerprint_map = {
                    k: set(v) for k, v in data.get("fingerprint_map", {}).items()
                }
                log_info(f"Loaded {len(self.profiles)} threat profiles from blacklist.")
            except Exception as e:
                log_warn(f"Could not load blacklist: {e}")

    def save(self):
        self._ensure_dir()
        with self._lock:
            data = {
                "profiles": [p.to_dict() for p in self.profiles.values()],
                "fingerprint_map": {k: list(v) for k, v in self.fingerprint_map.items()},
                "last_saved": datetime_now_iso(),
            }
            try:
                with open(BLACKLIST_FILE, "w") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                log_warn(f"Could not save blacklist: {e}")

    def record_attack(self, mac: str, technique: str, spoofed_ip: Optional[str] = None) -> ThreatProfile:
        mac = mac.lower()
        with self._lock:
            if mac not in self.profiles:
                self.profiles[mac] = ThreatProfile(mac)
                log_alert(f"New attacker added to blacklist: {mac}")

            profile = self.profiles[mac]
            old_level = profile.threat_level
            escalated = profile.record_attack(technique, spoofed_ip)

            if escalated:
                log_escalation(mac, old_level, profile.threat_level)

            # Update fingerprint map
            fp = profile.get_behavior_fingerprint()
            if fp:
                if fp not in self.fingerprint_map:
                    self.fingerprint_map[fp] = set()
                self.fingerprint_map[fp].add(mac)

                # Check if this fingerprint matches OTHER known MACs
                aliases = self.fingerprint_map[fp] - {mac}
                if aliases:
                    alias_str = ", ".join(aliases)
                    msg = f"MAC {mac} matches behavioral fingerprint of: {alias_str}"
                    log_warn(f"[FINGERPRINT MATCH] {msg}")
                    if msg not in profile.notes:
                        profile.notes.append(msg)
                    # Inherit the highest threat level from aliases
                    for alias_mac in aliases:
                        if alias_mac in self.profiles:
                            alias_lvl = self.profiles[alias_mac].threat_level
                            try:
                                alias_idx = THREAT_HIERARCHY.index(alias_lvl)
                                cur_idx = THREAT_HIERARCHY.index(profile.threat_level)
                                if alias_idx > cur_idx:
                                    profile.threat_level = alias_lvl
                                    log_escalation(mac, THREAT_HIERARCHY[cur_idx], alias_lvl,
                                                   reason="inherited from fingerprint match")
                            except ValueError:
                                pass

        # Auto-save
        self.save()
        return profile

    def get_threat_level(self, mac: str) -> Optional[str]:
        mac = mac.lower()
        with self._lock:
            if mac in self.profiles:
                return self.profiles[mac].threat_level
        return None

    def get_countermeasure_profile(self, mac: str) -> Dict[str, Any]:
        mac = mac.lower()
        level = self.get_threat_level(mac)
        if level:
            return COUNTERMEASURE_PROFILE.get(level, COUNTERMEASURE_PROFILE[THREAT_MONITOR])
        return COUNTERMEASURE_PROFILE[THREAT_MONITOR]

    def get_status_report(self) -> List[str]:
        with self._lock:
            lines = []
            for mac, p in sorted(self.profiles.items(), key=lambda x: x[1].total_attacks, reverse=True):
                lines.append(
                    f"  {mac}  │ {p.threat_level:8s} │ {p.total_attacks:4d} attacks │ "
                    f"techniques: {', '.join(p.techniques)} │ last: {p.last_seen}"
                )
            return lines

def datetime_now_iso() -> str:
    from datetime import datetime
    return datetime.now().isoformat()
