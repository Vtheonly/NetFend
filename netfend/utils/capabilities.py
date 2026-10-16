"""Capability probing (ADR-005): every external dependency is optional.

Probed once at startup; results drive feature enablement and WARNING
events. Missing capabilities NEVER crash the engine — they degrade
features with clear reporting (owner requirement #6.8).
"""
import os
import shutil
import subprocess
from typing import Any, Dict

_PROBED: Dict[str, Any] = {}

_OPTIONAL_TOOLS = ("nft", "ip", "ping", "iw", "nmcli", "systemctl", "resolvectl", "journalctl", "nft --version")


def _which(tool: str) -> bool:
    return shutil.which(tool.split()[0]) is not None


def probe() -> Dict[str, Any]:
    """Probe the runtime environment. Pure-side-effect-free (cached)."""
    global _PROBED
    if _PROBED:
        return _PROBED

    caps: Dict[str, Any] = {
        "root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
        "linux": os.name == "posix" and os.path.exists("/proc/net/dev"),
    }

    # Python modules
    try:
        import scapy  # noqa: F401
        caps["scapy"] = True
    except ImportError:
        caps["scapy"] = False

    try:
        import psutil  # noqa: F401
        caps["psutil"] = True
    except ImportError:
        caps["psutil"] = False

    try:
        import colorama  # noqa: F401
        caps["colorama"] = True
    except ImportError:
        caps["colorama"] = False

    # External tools
    for tool in ("nft", "ip", "ping", "iw", "nmcli", "systemctl",
                 "resolvectl", "journalctl"):
        caps[tool] = _which(tool)

    # nftables kernel support (nft binary present AND can list its own tables)
    caps["nftables"] = False
    if caps["nft"] and caps["root"]:
        try:
            r = subprocess.run(["nft", "list", "tables"], capture_output=True, timeout=5)
            caps["nftables"] = r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            caps["nftables"] = False

    # Wireless extensions: iw present AND at least one phy exists
    caps["wireless"] = False
    if caps["iw"]:
        try:
            r = subprocess.run(["iw", "dev"], capture_output=True, timeout=5)
            caps["wireless"] = r.returncode == 0 and b"Interface" in r.stdout
        except (OSError, subprocess.SubprocessError):
            caps["wireless"] = False

    # Monitor-mode capability (for deauth visibility — may require root)
    caps["monitor_mode"] = False
    if caps["iw"] and caps["root"]:
        try:
            r = subprocess.run(["iw", "phy"], capture_output=True, timeout=5)
            caps["monitor_mode"] = (
                r.returncode == 0
                and b"monitor" in r.stdout
            )
        except (OSError, subprocess.SubprocessError):
            caps["monitor_mode"] = False

    # systemd running (not just installed)
    caps["systemd_running"] = False
    if caps["systemctl"]:
        try:
            r = subprocess.run(
                ["systemctl", "is-system-running"], capture_output=True, timeout=5
            )
            caps["systemd_running"] = r.returncode in (0, 1)  # degraded still counts
        except (OSError, subprocess.SubprocessError):
            caps["systemd_running"] = False

    _PROBED = caps
    return caps


def get(name: str, default: Any = None) -> Any:
    return probe().get(name, default)


def have(name: str) -> bool:
    return bool(probe().get(name))


def missing_critical() -> list:
    """Capabilities whose absence disables core protection (vs. degrades)."""
    caps = probe()
    missing = []
    if not caps["linux"]:
        missing.append("linux (/proc)")
    if not caps["ip"]:
        missing.append("ip (iproute2)")
    return missing


def summary() -> Dict[str, Any]:
    """Human/dashboard-friendly capability snapshot."""
    caps = probe()
    notes = []
    if not caps["root"]:
        notes.append("not running as root: kernel enforcement (firewall, static ARP) disabled — dry-run/diagnostics mode")
    if not caps["nftables"]:
        notes.append("nftables unavailable: firewall rules not enforced (install nftables or run as root)")
    if not caps["scapy"]:
        notes.append("scapy not installed: ARP/DHCP packet inspection disabled (python3 -m pip install scapy)")
    if not caps["wireless"]:
        notes.append("no wireless tools/hardware visible: Wi-Fi diagnostics limited")
    if not caps["monitor_mode"]:
        notes.append("monitor mode not available: frame-level deauth detection impossible; enable 802.11w/PMF on the router instead")
    if not caps["systemd_running"]:
        notes.append("systemd not detected: service management commands unavailable")
    if not caps["journalctl"]:
        notes.append("journalctl unavailable: wpa_supplicant reason-code watch "
                     "(wifi.deauth_signature deauth-flood detection) disabled")
    return {"capabilities": caps, "notes": notes}
