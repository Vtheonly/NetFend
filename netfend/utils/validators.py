"""Input validators — every value that reaches a subprocess command line or a
firewall ruleset MUST pass through here first (AGENTS.md §4).

Pure functions, no I/O — unit-testable everywhere.
"""
import re

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)
IFACE_RE = re.compile(r"^[a-zA-Z0-9._-]{1,15}$")
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,63}$")
PORT_RE = re.compile(r"^[0-9]{1,5}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


def valid_mac(value) -> bool:
    return isinstance(value, str) and bool(MAC_RE.match(value))


def normalize_mac(value: str) -> str:
    """Returns lowercase MAC, or raises ValueError."""
    if not valid_mac(value):
        raise ValueError(f"invalid MAC address: {value!r}")
    return value.lower()


def valid_ipv4(value) -> bool:
    return isinstance(value, str) and bool(IPV4_RE.match(value))


def valid_interface(value) -> bool:
    return isinstance(value, str) and bool(IFACE_RE.match(value))


def valid_hostname(value) -> bool:
    return isinstance(value, str) and bool(HOSTNAME_RE.match(value))


def valid_port(value) -> bool:
    if isinstance(value, int):
        return 0 < value < 65536
    if isinstance(value, str) and PORT_RE.match(value):
        return 0 < int(value) < 65536
    return False


def valid_ports(values) -> bool:
    return isinstance(values, (list, tuple)) and all(valid_port(v) for v in values)
