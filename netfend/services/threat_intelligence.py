"""ThreatIntelligence — behavioral profiles + MAC-alias correlation.

Kept from the original (good design, audit §4): escalation ladder,
timing fingerprints that survive MAC changes, fingerprint-based alias
inheritance. Changed:
- saves are debounced (no disk write per attack event — audit RC-9)
- `summary()` for the dashboard (no printing inside the service)
"""
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from netfend.models.threat_profile import ThreatProfile
from netfend.utils.config import (
    BLACKLIST_FILE, THREAT_MONITOR, THREAT_HIERARCHY,
)
from netfend.utils.logging import log_info, log_warn, log_alert, log_escalation

_SAVE_DEBOUNCE_S = 10.0


class ThreatIntelligence:
    def __init__(self, path: Path = None):
        self.path = Path(path) if path else BLACKLIST_FILE
        self.profiles: Dict[str, ThreatProfile] = {}
        self.fingerprint_map: Dict[str, set] = {}
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
        with self._lock:
            if mac not in self.profiles:
                self.profiles[mac] = ThreatProfile(mac)
                log_alert(f"New attacker profile created: {mac}")

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
        self.save()  # debounced
        return profile

    def get_threat_level(self, mac: str) -> Optional[str]:
        mac = mac.lower()
        with self._lock:
            if mac in self.profiles:
                return self.profiles[mac].threat_level
        return None

    def summary(self) -> List[Dict[str, Any]]:
        """Dashboard/CLI view of known hostile profiles."""
        with self._lock:
            out = []
            for mac, p in sorted(self.profiles.items(),
                                  key=lambda x: x[1].total_attacks, reverse=True):
                out.append({
                    "mac": mac,
                    "threat_level": p.threat_level,
                    "total_attacks": p.total_attacks,
                    "techniques": sorted(p.techniques),
                    "spoofed_ips": sorted(p.spoofed_ips),
                    "first_seen": p.first_seen,
                    "last_seen": p.last_seen,
                    "notes": list(p.notes),
                })
            return out

    def get_status_report(self) -> List[str]:
        """Legacy text report (kept for CLI compatibility)."""
        return [
            f"  {r['mac']}  | {r['threat_level']:8s} | {r['total_attacks']:4d} attacks | "
            f"techniques: {', '.join(r['techniques'])} | last: {r['last_seen']}"
            for r in self.summary()
        ]

    def stop(self):
        if self._dirty:
            self.save(force=True)
