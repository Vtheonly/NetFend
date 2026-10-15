import json
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from netfend.utils.config import DATA_DIR, DEVICE_REGISTRY_FILE
from netfend.utils.logging import log_info, log_warn, log_success

class DeviceRegistry:
    """Manages the authorized/whitelisted and discovered local network devices."""

    def __init__(self):
        self.devices: Dict[str, Dict[str, Any]] = {}  # MAC (lowercase) -> Info Dict
        self._lock = threading.Lock()
        self._load()

    def _ensure_dir(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)

    def _load(self):
        self._ensure_dir()
        if DEVICE_REGISTRY_FILE.exists():
            try:
                with open(DEVICE_REGISTRY_FILE, "r") as f:
                    self.devices = json.load(f)
                log_info(f"Loaded {len(self.devices)} registered devices.")
            except Exception as e:
                log_warn(f"Could not load device registry: {e}")

    def save(self):
        self._ensure_dir()
        with self._lock:
            try:
                with open(DEVICE_REGISTRY_FILE, "w") as f:
                    json.dump(self.devices, f, indent=2)
            except Exception as e:
                log_warn(f"Could not save device registry: {e}")

    def register_device(self, mac: str, ip: str, hostname: str = "Unknown", is_authorized: bool = False, notes: str = "") -> bool:
        """Registers or updates a device in the registry."""
        mac = mac.lower()
        now = datetime.now().isoformat()
        with self._lock:
            if mac in self.devices:
                # Update existing device fields
                self.devices[mac]["last_ip"] = ip
                self.devices[mac]["last_seen"] = now
                if hostname and hostname != "Unknown":
                    self.devices[mac]["hostname"] = hostname
                if notes:
                    self.devices[mac]["notes"] = notes
                # Do not automatically override user-set is_authorized unless explicitly supplied
            else:
                self.devices[mac] = {
                    "mac": mac,
                    "last_ip": ip,
                    "hostname": hostname,
                    "is_authorized": is_authorized,
                    "first_seen": now,
                    "last_seen": now,
                    "notes": notes
                }
        self.save()
        return True

    def authorize_device(self, mac: str, authorize: bool = True) -> bool:
        mac = mac.lower()
        with self._lock:
            if mac in self.devices:
                self.devices[mac]["is_authorized"] = authorize
                self.save()
                return True
        return False

    def is_authorized(self, mac: str) -> bool:
        mac = mac.lower()
        with self._lock:
            if mac in self.devices:
                return self.devices[mac].get("is_authorized", False)
        return False

    def get_devices(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return dict(self.devices)
