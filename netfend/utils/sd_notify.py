"""Minimal systemd sd_notify support (no python-systemd dependency).

Sends READY=1 / STOPPING=1 / WATCHDOG=1 to the notify socket when the
engine runs under systemd (Type=notify). Silently no-ops otherwise.
"""
import os
import socket

_NOTIFIED = False


def _notify_socket() -> str:
    return os.environ.get("NOTIFY_SOCKET", "")


def available() -> bool:
    return bool(_notify_socket())


def notify(message: str) -> bool:
    global _NOTIFIED
    sock_path = _notify_socket()
    if not sock_path:
        return False
    if sock_path.startswith("@"):
        sock_path = "\0" + sock_path[1:]  # abstract namespace socket
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(sock_path)
            s.sendall(message.encode("utf-8"))
        _NOTIFIED = True
        return True
    except OSError:
        return False


def notify_ready() -> bool:
    return notify("READY=1")


def notify_stopping() -> bool:
    return notify("STOPPING=1")
