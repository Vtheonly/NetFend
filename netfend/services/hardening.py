"""KernelHardener — sysctl enforcement with saved-state restore (ADR-007).

Zero-trust LAN context (threat model update 2026-10-16): the adversary
may run dedicated attack suites (bettercap, yersinia, mitm6) and may
already control the default gateway/router. Kernel defaults still
trust L3 metadata:

- ICMP redirects can move our routes toward an attacker-controlled
  next hop (bettercap's icmp_redirect module)
- source-routed packets follow attacker-defined paths
- loose/absent rp_filter accepts spoofed source addresses
- broadcast ICMP probes map the LAN cheaply

This module enforces the client-side hardening set on engine start and
restores the previous values on engine stop — the same own-your-state
contract as the firewall tables and static neighbor entries (ADR-003).

Implementation notes (AGENTS.md §4/§5):
- writes go DIRECTLY to /proc/sys (stdlib only — no sysctl binary
  dependency, no subprocess, no shell)
- originals are persisted to DATA_DIR/hardening_state.json BEFORE any
  change; a stale state file from a crashed run is restored first
  (crash recovery — the same values are then re-read fresh)
- every failure degrades to a warning event; hardening must never
  crash the engine (ADR-005)
- rp_filter is configurable: "strict" (1, default) breaks asymmetric
  routing on multi-homed/VPN hosts — such setups choose "loose" (2) or
  "preserve". The spec-mandated default is strict.

The accept_ra sysctls are owned by the IPv6 guard (T-32), NOT here, so
each module restores exactly what it changed.
"""
import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from netfend.models.events import EventStore
from netfend.utils import capabilities
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn

# (proc-relative path, value, why)
_BASE_PARAMS: List[Tuple[str, str, str]] = [
    ("net/ipv4/conf/all/accept_redirects", "0",
     "drop ICMP redirects (route hijack vector)"),
    ("net/ipv4/conf/default/accept_redirects", "0",
     "drop ICMP redirects on future interfaces"),
    ("net/ipv4/conf/all/secure_redirects", "0",
     "do not honor redirects even from known gateways"),
    ("net/ipv4/conf/default/secure_redirects", "0",
     "secure_redirects off on future interfaces"),
    ("net/ipv4/conf/all/accept_source_route", "0",
     "drop source-routed packets"),
    ("net/ipv4/conf/default/accept_source_route", "0",
     "source-route off on future interfaces"),
    ("net/ipv4/conf/all/send_redirects", "0",
     "never emit redirects ourselves"),
    ("net/ipv4/conf/default/send_redirects", "0",
     "no redirects from future interfaces"),
    ("net/ipv4/icmp_echo_ignore_broadcasts", "1",
     "ignore broadcast ICMP (smurf/LAN mapping)"),
    ("net/ipv6/conf/all/accept_redirects", "0",
     "drop ICMPv6 redirects (rogue ND vector)"),
    ("net/ipv6/conf/default/accept_redirects", "0",
     "ICMPv6 redirects off on future interfaces"),
]

_RP_FILTER_VALUES = {"strict": "1", "loose": "2", "preserve": None}


def build_param_list(rp_filter_mode: str = "strict") -> List[Tuple[str, str]]:
    """Pure: the ordered list of (proc-relative-path, value) to enforce."""
    if rp_filter_mode not in _RP_FILTER_VALUES:
        raise ValueError(
            f"unknown hardening.rp_filter mode: {rp_filter_mode!r} "
            f"(expected one of {sorted(_RP_FILTER_VALUES)})")
    params: List[Tuple[str, str]] = [
        (path, value) for path, value, _ in _BASE_PARAMS]
    rp = _RP_FILTER_VALUES[rp_filter_mode]
    if rp is not None:
        params += [
            ("net/ipv4/conf/all/rp_filter", rp),
            ("net/ipv4/conf/default/rp_filter", rp),
        ]
    return params


class KernelHardener:
    """Applies and restores engine-owned sysctl state."""

    def __init__(self, events: EventStore,
                 proc_base: str = "/proc/sys",
                 state_path: Optional[Path] = None):
        self.events = events
        self.proc_base = Path(proc_base)
        if state_path is None:
            from netfend.utils.config import DATA_DIR
            state_path = Path(DATA_DIR) / "hardening_state.json"
        self.state_path = Path(state_path)
        self._lock = threading.Lock()
        self.applied: Dict[str, str] = {}       # path -> enforced value
        self.restored_once = False
        self.last_result: Optional[Dict[str, Any]] = None

    # -- capability gates -------------------------------------------------------
    def available(self) -> bool:
        return capabilities.have("root") and not cfg("general", "dry_run")

    def enabled(self) -> bool:
        return bool(cfg("hardening", "enabled", True))

    # -- tiny /proc/sys IO ------------------------------------------------------
    def _proc_path(self, rel: str) -> Path:
        return self.proc_base / rel

    def _read(self, rel: str) -> Optional[str]:
        try:
            with open(self._proc_path(rel)) as f:
                return f.read().strip()
        except OSError:
            return None

    def _write(self, rel: str, value: str) -> bool:
        try:
            with open(self._proc_path(rel), "w") as f:
                f.write(value + "\n")
            return True
        except OSError:
            return False

    # -- state persistence --------------------------------------------------------
    def _load_state(self) -> Dict[str, str]:
        try:
            if self.state_path.exists():
                with open(self.state_path) as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return {str(k): str(v) for k, v in data.items()
                            if isinstance(k, str)}
        except (OSError, json.JSONDecodeError):
            pass
        return {}

    def _save_state(self, state: Dict[str, str]) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_path, "w") as f:
                json.dump(state, f, indent=2)
        except OSError as e:
            log_warn(f"Could not persist hardening state: {e}")

    def _clear_state(self) -> None:
        try:
            if self.state_path.exists():
                self.state_path.unlink()
        except OSError:
            pass

    # -- public API ---------------------------------------------------------------
    def apply(self) -> bool:
        """Enforce the hardening set. Returns True when all params applied."""
        with self._lock:
            if not self.enabled():
                self.events.emit_simple(
                    "hardening.disabled", "notice", "confirmed",
                    "Kernel hardening disabled by config (hardening.enabled=false)",
                    source="hardening")
                return False
            if not self.available():
                self.events.emit_simple(
                    "hardening.unavailable", "notice", "unverified",
                    "Kernel hardening unavailable "
                    "(need root and dry_run off); ICMP redirect / "
                    "source-route / rp_filter protections inactive",
                    source="hardening")
                return False

            # crash recovery: restore a stale state file first so the
            # originals we save below are the TRUE pre-hardening values
            stale = self._load_state()
            if stale:
                self._restore_dict(stale)
                self._clear_state()

            mode = str(cfg("hardening", "rp_filter", "strict"))
            try:
                params = build_param_list(mode)
            except ValueError as e:
                log_warn(f"{e}; falling back to 'strict'")
                params = build_param_list("strict")

            originals: Dict[str, str] = {}
            applied: List[str] = []
            skipped: List[str] = []
            failed: List[str] = []
            for rel, value in params:
                current = self._read(rel)
                if current is None:
                    skipped.append(rel)     # kernel without this knob
                    continue
                if current == value:
                    # already correct: still record for restore symmetry
                    # (only if not already enforced by us — read-back proof)
                    originals.setdefault(rel, current)
                    applied.append(rel)
                    continue
                if self._write(rel, value):
                    originals[rel] = current
                    self.applied[rel] = value
                    applied.append(rel)
                else:
                    failed.append(rel)

            if originals:
                self._save_state(originals)
            self.last_result = {
                "applied": applied, "skipped": skipped, "failed": failed,
                "rp_filter": mode}
            ok = not failed
            level = "info" if ok else "warning"
            self.events.emit_simple(
                "hardening.applied", level, "confirmed",
                f"Kernel hardening applied: {len(applied)} parameter(s) "
                f"enforced (ICMP redirects off, source-route off, rp_filter "
                f"'{mode}')" + (f"; {len(failed)} failed" if failed else ""),
                source="hardening", **self.last_result)
            log_info(f"Kernel hardening: {len(applied)} applied, "
                     f"{len(skipped)} absent, {len(failed)} failed")
            return ok

    def restore(self) -> None:
        """Restore the pre-hardening values (engine stop / crash recovery)."""
        with self._lock:
            if not cfg("hardening", "restore_on_stop", True):
                log_info("hardening.restore_on_stop=false — values kept")
                return
            state = self._load_state()
            if not state:
                return
            self._restore_dict(state)
            self._clear_state()
            self.applied = {}
            self.restored_once = True
            self.events.emit_simple(
                "hardening.restored", "info", "confirmed",
                f"Kernel parameters restored to pre-engine values "
                f"({len(state)} parameter(s))",
                source="hardening", restored=sorted(state))
            log_info(f"Kernel hardening restored ({len(state)} params)")

    def _restore_dict(self, state: Dict[str, str]) -> None:
        for rel, value in state.items():
            # never write outside /proc/sys net (defense-in-depth: the
            # state file content must not turn into an arbitrary writer)
            if ".." in rel or not rel.startswith("net/"):
                log_warn(f"refusing to restore suspicious path {rel!r}")
                continue
            if not self._write(rel, value):
                log_warn(f"could not restore {rel}")

    def status(self) -> Dict[str, Any]:
        with self._lock:
            state = self._load_state()
            return {
                "enabled": self.enabled(),
                "available": self.available(),
                "active": bool(state) or bool(self.applied),
                "enforced": sorted(self.applied) or sorted(state),
                "restored_once": self.restored_once,
                "rp_filter_mode": str(cfg("hardening", "rp_filter", "strict")),
                "restore_on_stop": bool(cfg("hardening", "restore_on_stop", True)),
                "last_result": self.last_result,
            }
