"""NetFend configuration.

Layers (lowest to highest precedence):
  1. Built-in DEFAULTS (below)
  2. /etc/netfend/config.json (or NETFEND_CONFIG env override)
  3. Explicit set_config() calls (used by CLI flags / dashboard reload)

All durations are seconds unless suffixed. Thresholds are deliberately
conservative: NetFend prefers a missed low-confidence signal over a false
accusation (see AGENTS.md rule 7).
"""
import json
import os
from pathlib import Path
from typing import Any, Dict

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
# Install-time location (may be read-only); runtime state always goes to
# DATA_DIR. Root installs use /var/lib/netfend; unprivileged runs fall back
# to ./data so the engine can run in dry-run/dev mode without root.
INSTALL_ETC_DIR = Path(os.environ.get("NETFEND_ETC", "/etc/netfend"))
CONFIG_FILE = INSTALL_ETC_DIR / "config.json"

def _default_data_dir() -> Path:
    env = os.environ.get("NETFEND_DATA_DIR")
    if env:
        return Path(env)
    var_dir = Path("/var/lib/netfend")
    try:
        var_dir.mkdir(parents=True, exist_ok=True)
        if os.access(var_dir, os.W_OK):
            return var_dir
    except OSError:
        pass
    return Path("./data").resolve()

DATA_DIR = _default_data_dir()

BLACKLIST_FILE = DATA_DIR / "blacklist.json"
DEVICE_REGISTRY_FILE = DATA_DIR / "devices.json"
EVENTS_FILE = DATA_DIR / "events.jsonl"
LOG_FILE = DATA_DIR / "netfend.log"
DASHBOARD_TOKEN_FILE = DATA_DIR / "dashboard.token"
STATE_FILE = DATA_DIR / "engine_state.json"

# --------------------------------------------------------------------------
# Threat levels (kept compatible with the original model)
# --------------------------------------------------------------------------
THREAT_MONITOR = "MONITOR"
THREAT_SUSPECT = "SUSPECT"
THREAT_HOSTILE = "HOSTILE"
THREAT_CRITICAL = "CRITICAL"

THREAT_HIERARCHY = [THREAT_MONITOR, THREAT_SUSPECT, THREAT_HOSTILE, THREAT_CRITICAL]

ESCALATION_RULES = {
    THREAT_MONITOR:  {"attacks_to_next": 3,  "window_secs": 120},
    THREAT_SUSPECT:  {"attacks_to_next": 5,  "window_secs": 300},
    THREAT_HOSTILE:  {"attacks_to_next": 15, "window_secs": 600},
    THREAT_CRITICAL: {"attacks_to_next": 999, "window_secs": 999},
}

# --------------------------------------------------------------------------
# Severity / confidence vocabulary for events
# --------------------------------------------------------------------------
SEV_INFO = "info"
SEV_NOTICE = "notice"
SEV_WARNING = "warning"
SEV_CRITICAL = "critical"
SEVERITIES = (SEV_INFO, SEV_NOTICE, SEV_WARNING, SEV_CRITICAL)

CONFIRMED = "confirmed"      # multiple independent indicators agree
SUSPECTED = "suspected"      # single indicator, within thresholds
UNVERIFIED = "unverified"    # observation without enough evidence
CONFIDENCE_LEVELS = (CONFIRMED, SUSPECTED, UNVERIFIED)

# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------
DEFAULTS: Dict[str, Any] = {
    "general": {
        "interface": None,              # auto-detect default route interface
        "dry_run": False,               # never touch kernel state (diagnostics only)
        "log_level": "INFO",
        "log_max_bytes": 2_000_000,     # per rotated file
        "log_backups": 3,
        "events_ring_size": 2000,       # in-memory event ring
        "events_file_max_bytes": 2_000_000,
        "event_dedup_window_s": 10,     # identical events fold into repeat_count (P-21)
    },
    "firewall": {
        "enabled": True,
        "profile": "standard",          # standard | strict | off
        "new_conn_rate_per_s": 50,      # per-source NEW connection rate limit
        "new_conn_burst": 100,
        "icmp_rate_per_s": 20,          # ICMP echo flood limit
        "icmp_burst": 40,
        "strict_allowed_tcp_ports": [], # for strict profile, e.g. [22]
        "strict_allowed_udp_ports": [53, 67, 68],
        "rollback_cooldown_s": 300,     # after a failed apply, wait before retry
        "selfcheck_timeout_s": 6,
    },
    "arp": {
        "enabled": True,
        "flap_window_s": 120,           # same IP seen with N distinct MACs within window
        "flap_mac_count": 3,            # ... => flapping event
        "gratuitous_rate_per_s": 10,    # gARP flood threshold per source MAC
        "gratuitous_burst": 25,
        "gateway_confirmations": 2,     # observations before treating gw MAC change as real
        "gateway_confirm_window_s": 60, # ... within this window
        "old_gw_silence_s": 120,        # pinned gw MAC silent this long => replacement candidate
        "gateway_change_cooldown_s": 300,  # per-MAC cooldown for gateway_change events
        "oscillation_window_s": 120,    # gateway MAC alternation window (P-19)
        "oscillation_min_transitions": 6,  # switches in window => oscillation, not change
        "corrective_arp_max": 5,        # bounded, event-triggered only (ADR-002/006)
        "corrective_arp_enabled": True,
        "corrective_arp_cooldown_s": 60,    # sporadic attacks: one burst per window
        "corrective_sustain_window_s": 12,  # triggers this close together = sustained attack (P-28)
        "corrective_sustain_interval_s": 5, # ... allow a burst this often while sustained
        "corrective_packets_per_minute": 30,  # sliding 60s airtime budget (hard ceiling 60)
    },
    "dhcp": {
        "enabled": True,
        "learn_observations": 2,        # learning window before rogue flagging
        "lease_watch": True,
    },
    "dns": {
        "enabled": True,
        "watch_interval_s": 5,
        "probe_interval_s": 60,
        "probe_domain": "example.com",  # resolved via system resolver; never custom server
        "probe_timeout_s": 5,
    },
    "wifi": {
        "enabled": True,
        "poll_interval_s": 10,
        "disconnect_count": 3,          # disconnects within window => suspicious pattern
        "disconnect_window_s": 300,
        "weak_signal_rssi": -80,        # dBm
    },
    "metrics": {
        "enabled": True,
        "sample_interval_s": 2,
        "ping_interval_s": 10,
        "ping_timeout_s": 1,
        "history_points": 600,          # ring buffer size for charts (~20 min at 2s)
    },
    "network_monitor": {
        "enabled": True,
        "settle_delay_s": 3,            # wait after change event before re-baselining
    },
    "dashboard": {
        "enabled": True,
        "bind": "127.0.0.1",
        "port": 8787,
        "allow_local_readonly": True,   # GET /api/* from localhost without token
        "login_rate_per_min": 10,
    },
}

_config: Dict[str, Any] = {}


def _deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Path = None) -> Dict[str, Any]:
    """Load and merge configuration; returns the effective config dict."""
    global _config
    path = path or CONFIG_FILE
    overlay: Dict[str, Any] = {}
    if path and Path(path).is_file():
        try:
            with open(path, "r") as f:
                overlay = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            # Config problems must never crash the engine (AGENTS.md §4).
            print(f"[netfend] WARNING: could not read config {path}: {e}; using defaults")
    _config = _deep_merge(DEFAULTS, overlay)
    # Environment override (CLI --dry-run sets NETFEND_DRY_RUN=1).
    # Applied last so it survives any load_config() re-read.
    if os.environ.get("NETFEND_DRY_RUN", "").lower() in ("1", "true", "yes"):
        _config["general"]["dry_run"] = True
    # Warn about keys that are not in DEFAULTS (compare against the base,
    # not the merged result — unknown keys would otherwise look "known")
    _warn_unknown_keys(DEFAULTS, overlay, prefix="")
    return _config


def _warn_unknown_keys(effective: Dict[str, Any], overlay: Dict[str, Any], prefix: str):
    for k, v in overlay.items():
        if k not in effective:
            print(f"[netfend] WARNING: unknown config key '{prefix}{k}' ignored")
        elif isinstance(v, dict) and isinstance(effective[k], dict):
            _warn_unknown_keys(effective[k], v, prefix=f"{prefix}{k}.")


def get_config() -> Dict[str, Any]:
    if not _config:
        return load_config()
    return _config


def set_config(section: str, key: str, value: Any) -> None:
    """Runtime override (CLI flags / dashboard reload). Validates section/key exist."""
    cfg = get_config()
    if section not in cfg or not isinstance(cfg[section], dict):
        raise KeyError(f"unknown config section '{section}'")
    if key not in cfg[section]:
        raise KeyError(f"unknown config key '{section}.{key}'")
    cfg[section][key] = value


def cfg(section: str, key: str = None, default: Any = None) -> Any:
    """Convenience accessor: cfg('arp', 'flap_window_s')."""
    c = get_config()
    sec = c.get(section, {})
    if key is None:
        return sec
    return sec.get(key, default)
