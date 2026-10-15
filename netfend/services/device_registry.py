"""DeviceRegistry — observed local devices (observation ONLY, never enforcement).

Extended from the original (kept: data model, authorize workflow) with:
- `save=False` support for debounced persistence (audit RC-9: the old code
  rewrote the JSON on EVERY sniffed ARP packet)
- observation metadata (vendor lookup disabled by default — no external deps)

IMPORTANT (ADR-001): registration state NEVER triggers any action against
a device. It exists for the topology view and for the user's own
authorization bookkeeping.
"""
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from netfend.utils.config import DATA_DIR, DEVICE_REGISTRY_FILE
from netfend.utils.logging import log_info, log_warn


class DeviceRegistry:
    def __init__(self, path: Path = None):
        self.path = Path(path) if path else DEVICE_REGISTRY_FILE
        self.devices: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._load()

    def _ensure_dir(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def _load(self):
        try:
            if self.path.exists():
                with open(self.path, "r") as f:
                    self.devices = json.load(f)
                log_info(f"Loaded {len(self.devices)} registered devices.")
        except (OSError, json.JSONDecodeError) as e:
            log_warn(f"Could not load device registry: {e}")

    def save(self) -> bool:
        with self._lock:
            try:
                self._ensure_dir()
                with open(self.path, "w") as f:
                    json.dump(self.devices, f, indent=2)
                return True
            except OSError as e:
                log_warn(f"Could not save device registry: {e}")
                return False

    def register_device(self, mac: str, ip: str, hostname: str = "Unknown",
                        is_authorized: bool = False, notes: str = "",
                        save: bool = True) -> bool:
        """Register or update an observed device.

        `save=False` enables debounced batch persistence from hot paths
        (packet callbacks). Existing authorization flags are never
        overwritten by passive observation.
        """
        mac = mac.lower()
        now = datetime.now().isoformat()
        with self._lock:
            if mac in self.devices:
                d = self.devices[mac]
                if ip:
                    d["last_ip"] = ip
                d["last_seen"] = now
                if hostname and hostname != "Unknown":
                    d["hostname"] = hostname
                if notes:
                    d["notes"] = notes
            else:
                self.devices[mac] = {
                    "mac": mac,
                    "last_ip": ip or "",
                    "hostname": hostname,
                    "is_authorized": is_authorized,
                    "first_seen": now,
                    "last_seen": now,
                    "notes": notes,
                }
        if save:
            self.save()
        return True

    def authorize_device(self, mac: str, authorize: bool = True) -> bool:
        mac = mac.lower()
        with self._lock:
            if mac in self.devices:
                self.devices[mac]["is_authorized"] = authorize
        return self.save() and mac in self.devices

    def is_authorized(self, mac: str) -> bool:
        mac = mac.lower()
        with self._lock:
            return self.devices.get(mac, {}).get("is_authorized", False)

    def get_devices(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {k: dict(v) for k, v in self.devices.items()}

    def forget(self, mac: str) -> bool:
        mac = mac.lower()
        with self._lock:
            existed = mac in self.devices
            if existed:
                del self.devices[mac]
        # save() takes the lock itself — must NOT be called while holding it
        return self.save() if existed else False
