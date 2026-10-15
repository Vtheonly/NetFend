import os
from pathlib import Path

# Paths
DATA_DIR = Path("/var/lib/netfend")
# Fallback to current directory if /var/lib/netfend is not writable/accessible
if not os.access(DATA_DIR.parent, os.W_OK):
    DATA_DIR = Path("./data")

BLACKLIST_FILE = DATA_DIR / "blacklist.json"
DEVICE_REGISTRY_FILE = DATA_DIR / "devices.json"
LOG_FILE = DATA_DIR / "netfend.log"

# Threat Levels
THREAT_MONITOR = "MONITOR"    # First sighting / anomalous activity
THREAT_SUSPECT = "SUSPECT"    # Repeated anomalies
THREAT_HOSTILE = "HOSTILE"    # Confirmed active attacker
THREAT_CRITICAL = "CRITICAL"   # Persistent, aggressive attacker

THREAT_HIERARCHY = [THREAT_MONITOR, THREAT_SUSPECT, THREAT_HOSTILE, THREAT_CRITICAL]

# Escalation Rules
ESCALATION_RULES = {
    THREAT_MONITOR:  {"attacks_to_next": 3,   "window_secs": 120},
    THREAT_SUSPECT:  {"attacks_to_next": 5,   "window_secs": 300},
    THREAT_HOSTILE:  {"attacks_to_next": 15,  "window_secs": 600},
    THREAT_CRITICAL: {"attacks_to_next": 999, "window_secs": 999},
}

# Countermeasure intensity profile
COUNTERMEASURE_PROFILE = {
    THREAT_MONITOR:  {"blast_count": 3,   "blast_interval": 0.05, "loop_sleep": 1.0},
    THREAT_SUSPECT:  {"blast_count": 8,   "blast_interval": 0.02, "loop_sleep": 0.5},
    THREAT_HOSTILE:  {"blast_count": 15,  "blast_interval": 0.01, "loop_sleep": 0.2},
    THREAT_CRITICAL: {"blast_count": 30,  "blast_interval": 0.005, "loop_sleep": 0.05},
}
