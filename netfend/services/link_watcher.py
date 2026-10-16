"""LinkWatcher — boot-early 802.11 link-evidence recorder (P-44).

Owner requirement (2026-10-16, after the factory-reset incident): know
WHAT happens from the very first connection attempt of every boot —
BEFORE the engine (After=network-online.target) or any manual command
starts. The engine's SupplicantMonitor only sees events from engine
start; the auth/assoc rejections that decide the owner's morning
happen before that. This module is the missing early observer.

Sources (all read-only — this daemon NEVER touches kernel state, so it
can never fight the defense engine; P-41 discipline):
  `iw event -f`     kernel 802.11 management events (auth/assoc/deauth)
  journalctl (-b)   wpa_supplicant reason codes + NM activation lines,
                    backfilled from the start of the current boot
  state polls       iw link + ip addr/route/neigh + one gateway ping
Everything lands in ONE append-only JSONL evidence log, and every
record is annotated with the interface MAC in use at observation time —
the piece that makes the identity A/B experiment (identity_lab.py)
interpretable afterwards: real-identity deauths vs random-identity
deauths are distinguishable without trusting anyone's memory.

Division of labor: the ENGINE keeps the alerting role
(wifi.deauth_signature in --events/dashboard); the watcher keeps the
EVIDENCE role (its own link-evidence.jsonl, its own pattern records).
The journal is read by both processes — harmless, it is read-only.

Cross-process contract: the watcher owns rotation of link-evidence.jsonl
(keeps one predecessor `.jsonl.1`); external writers (the A/B runner's
phase markers) use append_marker(), which opens per write so a rotation
between two marker writes can never splice a line across files. Queries
read current + rotated predecessor so evidence spanning a rotation
stays queryable.
"""
import fcntl
import json
import os
import queue
import re
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from netfend.services.network_manager import parse_default_route, parse_neigh_output
from netfend.services.wifi_diagnostics import (
    classify_deauth_signature,
    parse_iw_link,
    parse_journal_line,
    parse_supplicant_disconnect,
)
from netfend.utils import capabilities
from netfend.utils import config as config_mod
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn

_TIMEOUT = 6
_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
_RE_IFACE_PREFIX = re.compile(
    r"^(?:phy#\d+,\s*)?([\w.-]+)(?:\s+\(phy #\d+\))?:\s*(.*)$")

_MAX_SUPPLICANT_OBS = 200
_MAX_JOURNAL_FAILURES = 5
_MAX_IW_RESTARTS = 6


def _run(cmd: List[str], timeout: int = _TIMEOUT) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _evidence_path(path: Path = None) -> Path:
    """Resolve the evidence log path at CALL time (tests re-point the
    config module attribute; a module-level import would freeze it)."""
    return Path(path) if path else Path(config_mod.LINK_EVIDENCE_FILE)


# ---------------------------------------------------------------------------
# Pure parsers (unit-testable without any wireless hardware)
# ---------------------------------------------------------------------------

def parse_iw_event_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one `iw event -f` line into a record dict (or None).

    iw's event formatting varies across versions (with/without a phy
    suffix, frequency in parentheses, 'status:' vs 'status', one or two
    MAC arguments), so this parser keys on the event KEYWORD and
    extracts what it can — the raw line is ALWAYS kept. Unknown lines
    become kind='other': an evidence recorder must never drop a line it
    does not understand.
    """
    m = _RE_IFACE_PREFIX.match(line.strip())
    if not m or not m.group(2):
        return None
    iface, rest = m.group(1), m.group(2)
    rec: Dict[str, Any] = {"iface": iface, "raw": line.strip()}
    first_two = " ".join(rest.split()[:2]).lower()
    if first_two.startswith("scan"):
        rec["kind"] = "scan"
    elif first_two in ("new station", "del station"):
        rec["kind"] = "station"
    elif first_two in ("new interface", "del interface", "new peer",
                       "del peer"):
        rec["kind"] = "iface_evt"
    else:
        kw = rest.split(None, 1)[0].lower()
        rec["kind"] = {
            "auth": "auth", "assoc": "assoc", "deauth": "deauth",
            "disassoc": "disassoc", "connect": "connect",
            "disconnect": "disconnect", "roam": "roam",
            "station": "station", "cqm": "cqm", "radar": "radar",
            "mgmt": "mgmt_register", "mesh": "mesh", "chan": "channel",
            "regulatory": "regulatory", "wiphy": "wiphy",
            "vendor": "vendor", "command": "command",
        }.get(kw, "other")
    fm = re.search(r"(?:on|at)\s+(\d+(?:\.\d+)?)\s*MHz", rest)
    if fm:
        try:
            rec["freq"] = float(fm.group(1))
        except ValueError:
            pass
    sm = re.search(r"status:?\s*(\d+)", rest)
    if sm:
        rec["status"] = int(sm.group(1))
    rm = re.search(r"reason[:=]?\s*(\d+)", rest)
    if rm:
        rec["reason"] = int(rm.group(1))
    b = _MAC_RE.search(rest)
    if b:
        rec["bssid_or_peer"] = b.group(0).lower()
    return rec


def parse_ip_link_mac(output: str) -> Optional[str]:
    """Extract the link/ether MAC from `ip link show IF` output."""
    for line in output.splitlines():
        m = re.search(r"link/ether\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", line,
                      re.IGNORECASE)
        if m:
            return m.group(1).lower()
    return None


def parse_iw_link_ext(output: str) -> Dict[str, Any]:
    """parse_iw_link plus BSSID and frequency (evidence-grade detail)."""
    info = parse_iw_link(output)
    m = re.search(r"Connected to\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", output,
                  re.IGNORECASE)
    if m:
        info["bssid"] = m.group(1).lower()
    m = re.search(r"freq:\s*(\d+)", output)
    if m:
        info["freq"] = int(m.group(1))
    return info


def band_from_freq(freq) -> Optional[str]:
    """Frequency (MHz) -> band label. Accepts ints/floats/None."""
    if freq is None:
        return None
    try:
        f = float(freq)
    except (TypeError, ValueError):
        return None
    if 2400 <= f < 2500:
        return "2.4 GHz"
    if 4900 <= f < 5900:
        return "5 GHz"
    if 5900 <= f < 7300:
        return "6 GHz"
    return None


def format_record(rec: Dict[str, Any]) -> str:
    """One-line human rendering of an evidence record (CLI `wifi events`)."""
    ts = rec.get("iso") or datetime.fromtimestamp(
        rec.get("ts", 0)).strftime("%Y-%m-%d %H:%M:%S")
    bits = [f"{rec.get('kind', '?'):18s}"]
    if rec.get("phase"):
        bits.append(f"phase={rec['phase']}")
    if rec.get("reason") is not None:
        bits.append(f"reason={rec['reason']}")
    if rec.get("locally_generated") is not None:
        bits.append(f"lg={rec['locally_generated']}")
    if rec.get("bssid") or rec.get("bssid_or_peer"):
        bits.append(f"bssid={rec.get('bssid') or rec.get('bssid_or_peer')}")
    if rec.get("status") is not None:
        bits.append(f"status={rec['status']}")
    if rec.get("associated") is not None:
        bits.append("assoc" if rec["associated"] else "down")
    if rec.get("ip"):
        bits.append(f"ip={rec['ip']}")
    if rec.get("gw_mac"):
        bits.append(f"gw={rec['gw_mac']}")
    if rec.get("gw_ok"):
        bits.append("gw_ok")
    if rec.get("band"):
        bits.append(str(rec["band"]))
    if rec.get("rssi") is not None:
        bits.append(f"{rec['rssi']}dBm")
    if rec.get("mac_in_use"):
        bits.append(f"mac={rec['mac_in_use']}")
    detail = rec.get("detail") or rec.get("raw")
    if detail:
        bits.append(f"| {str(detail)[:110]}")
    return f"{ts}  " + " ".join(bits)


def summarize_window(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Counts for reports: what did this window of evidence show?"""
    incoming = [r for r in records
                if r.get("kind") in ("deauth", "disassoc")
                and r.get("locally_generated") == 0]
    client = [r for r in records
              if r.get("kind") in ("deauth", "disassoc")
              and r.get("locally_generated") == 1]
    states = [r for r in records if r.get("kind") == "state"]
    reasons: Dict[int, int] = {}
    for r in incoming:
        try:
            reasons[int(r["reason"])] = reasons.get(int(r["reason"]), 0) + 1
        except (KeyError, TypeError, ValueError):
            pass
    return {
        "records": len(records),
        "incoming_deauths": len(incoming),
        "client_deauths": len(client),
        "iw_auth_events": sum(1 for r in records if r.get("kind") == "auth"),
        "assoc_successes": sum(1 for r in records if r.get("kind") == "assoc"),
        "assoc_attempts": sum(1 for r in records
                              if r.get("kind") == "assoc_attempt"),
        "auth_rejects": sum(1 for r in records
                            if r.get("kind") == "auth_rejected"),
        "state_snapshots": len(states),
        "connected_snapshots": sum(1 for r in states if r.get("associated")),
        "deauth_bursts": sum(1 for r in records
                             if r.get("kind") == "deauth_burst"),
        "gateway_macs": sorted({r["gw_mac"] for r in states if r.get("gw_mac")}),
        "gateway_flaps": sum(1 for r in records
                             if r.get("kind") == "gateway_flap"),
        "incoming_reason_counts": {str(k): v for k, v in sorted(reasons.items())},
    }


# ---------------------------------------------------------------------------
# EvidenceLog — append-only JSONL with single rotation
# ---------------------------------------------------------------------------

class EvidenceLog:
    """Append-only JSONL evidence log; one record per line.

    Rotation keeps exactly one predecessor (path + '.jsonl.1'); queries
    read both files so evidence spanning a rotation stays queryable.
    The WATCHER owns rotation. External processes must not hold this
    handle — they use append_marker() instead.
    """

    def __init__(self, path: Path = None, max_bytes: int = None):
        self.path = _evidence_path(path)
        self.max_bytes = (max_bytes if max_bytes is not None
                          else int(cfg("wifi", "evidence_max_bytes", 5_000_000)))
        self._fh = None
        self._bytes = 0
        self.records_written = 0
        self._open()

    def _open(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.path, "a", encoding="utf-8")
            self._fh.seek(0, os.SEEK_END)
            self._bytes = self._fh.tell()
        except OSError:
            self._fh = None  # degraded: in-memory attempts still go to disk
            # via append_marker per write; persistence must never crash us

    def append(self, rec: Dict[str, Any]) -> None:
        line = _encode_record(rec)
        if self._fh is None:
            append_marker(self.path, rec)
            self.records_written += 1
            return
        if self._bytes + len(line.encode("utf-8")) > self.max_bytes:
            self._rotate()
            if self._fh is None:
                append_marker(self.path, rec)
                self.records_written += 1
                return
        try:
            self._fh.write(line)
            self._fh.flush()
            self._bytes += len(line.encode("utf-8"))
            self.records_written += 1
        except OSError:
            self._fh = None

    def _rotate(self):
        try:
            self._fh.close()
        except OSError:
            pass
        try:
            prev = self.path.with_name(self.path.name + ".1")
            if prev.exists():
                prev.unlink()
            self.path.rename(prev)
        except OSError:
            pass
        try:
            self._fh = open(self.path, "a", encoding="utf-8")
            self._bytes = 0
        except OSError:
            self._fh = None

    def close(self):
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None


def _encode_record(rec: Dict[str, Any]) -> str:
    rec.setdefault("ts", time.time())
    if not rec.get("iso"):
        try:
            rec["iso"] = datetime.fromtimestamp(
                rec["ts"]).astimezone().isoformat(timespec="milliseconds")
        except (OverflowError, OSError, ValueError):
            rec["iso"] = ""
    return json.dumps(rec, default=str) + "\n"


def append_marker(path: Path, rec: Dict[str, Any]) -> None:
    """Cross-process marker append (A/B phases, notes).

    Opens per write with O_APPEND semantics (regular append mode): a
    rotation by the watcher between two marker writes can never splice
    a line across files. Failures are swallowed — markers are evidence
    annotations, never control flow.
    """
    try:
        target = _evidence_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as f:
            f.write(_encode_record(rec))
    except OSError:
        pass


def evidence_query(path: Path = None, since: float = None, until: float = None,
                   kinds: Iterable[str] = None, limit: int = None
                   ) -> List[Dict[str, Any]]:
    """Read evidence records (current + rotated predecessor), filtered.

    Returns chronologically sorted records; `limit` keeps the NEWEST N.
    """
    base = _evidence_path(path)
    files = [base.with_name(base.name + ".1"), base]   # rotated first
    kindset = set(kinds) if kinds else None
    out: List[Dict[str, Any]] = []
    for f in files:
        try:
            if not f.exists():
                continue
            with open(f, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue   # torn line (crash mid-write): skip, never crash
                    ts = rec.get("ts", 0)
                    if since is not None and ts < since:
                        continue
                    if until is not None and ts > until:
                        continue
                    if kindset and rec.get("kind") not in kindset:
                        continue
                    out.append(rec)
        except OSError:
            continue
    out.sort(key=lambda r: r.get("ts", 0))
    if limit is not None:
        out = out[-limit:] if limit > 0 else []
    return out


# ---------------------------------------------------------------------------
# Single-instance lock (P-41 pattern)
# ---------------------------------------------------------------------------

def acquire_lock(path: str):
    """flock single-instance guard. Returns (fd, conflict_pid_or_None)."""
    fd = None
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        try:
            fallback = Path(config_mod.DATA_DIR) / Path(path).name
            fd = os.open(fallback, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError:
            return None, None   # locking impossible: degrade, continue
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        holder = ""
        try:
            os.lseek(fd, 0, 0)
            holder = os.read(fd, 64).decode(errors="replace").strip()
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass
        return None, (holder or "unknown")
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
    except OSError:
        pass
    return fd, None


# ---------------------------------------------------------------------------
# LinkWatcher
# ---------------------------------------------------------------------------

# Journal lines worth recording (allowlist — the journal is chatty and
# the state poller already carries the structure; these add the WHY).
_JOURNAL_KEYWORDS = (
    "CTRL-EVENT-DISCONNECTED", "CTRL-EVENT-ASSOC",
    "Trying to associate", "Association request",
    "Authentication with", "auth fails", "Authentication rejected",
    "activation of connection",
)


class LinkWatcher:
    """Long-running read-only link evidence recorder.

    One main loop + one iw-event reader thread (daemon). The journal
    poller reuses the P-43 bounded pattern: --since watermark,
    microsecond dedup, consecutive-failure give-up. The state poller
    records on CHANGE plus a heartbeat, and detects two evidence-grade
    patterns: deauth bursts (reusing classify_deauth_signature) and
    gateway-MAC flapping while associated (NetCut-class ARP spoof or a
    legitimate router HA pair — recorded, never auto-classified;
    AGENTS.md rule 7).
    """

    def __init__(self, path: Path = None, run=None):
        self._run = run or _run
        self._stop = threading.Event()
        self._iw_proc: Optional[subprocess.Popen] = None
        self._iw_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._iw_restarts = 0
        self._iw_last_restart = 0.0
        self._iface: Optional[str] = None
        self._mac_in_use: Optional[str] = None
        self._no_iface_noted = False
        self._journal_watermark = 0.0   # 0 = backfill whole (current) boot
        self._journal_failures = 0
        self._journal_gave_up = False
        self._supplicant_obs: List[Dict[str, Any]] = []
        self._last_state_key = None
        self._last_heartbeat = 0.0
        self._gw_history: List[Dict[str, Any]] = []
        self._last_pattern: Dict[str, float] = {}
        self.started_at: Optional[float] = None
        self.log = EvidenceLog(path)

    # -- lifecycle ---------------------------------------------------------

    def start(self):
        self.started_at = time.time()
        self._record({"kind": "note", "source": "watcher",
                      "detail": "link watcher started (boot-early evidence "
                                "recorder; read-only observer)"})
        if not capabilities.have("journalctl"):
            self._record({"kind": "note", "source": "watcher",
                          "detail": "journalctl unavailable — supplicant "
                                    "reason codes not recorded (state polls "
                                    "and iw events continue)"})
        self._start_iw_events()

    def stop(self):
        self._stop.set()

    def run_forever(self):
        self.start()
        last_journal = 0.0
        last_state = 0.0
        while not self._stop.is_set():
            now = time.time()
            self._drain_iw_queue()
            if self._iw_proc is not None and self._iw_proc.poll() is not None:
                self._maybe_restart_iw(now)
            if now - last_journal >= float(
                    cfg("wifi", "watcher_journal_poll_s", 5)):
                last_journal = now
                self._journal_poll(now)
            if now - last_state >= float(cfg("wifi", "watcher_poll_s", 10)):
                last_state = now
                self._state_poll(now)
            self._stop.wait(0.5)
        self._shutdown()
        return 0

    def _shutdown(self):
        if self._iw_proc is not None:
            try:
                self._iw_proc.terminate()
            except OSError:
                pass
        self._record({"kind": "note", "source": "watcher",
                      "detail": "link watcher stopped "
                                f"({self.log.records_written} records written)"})
        self.log.close()
        log_info(f"link watcher stopped ({self.log.records_written} records)")

    # -- iw event source ----------------------------------------------------

    def _start_iw_events(self):
        if not capabilities.have("iw"):
            self._record({"kind": "note", "source": "watcher",
                          "detail": "iw not available — kernel 802.11 events "
                                    "not recorded (journal + state polls "
                                    "continue)"})
            return
        try:
            self._iw_proc = subprocess.Popen(
                ["iw", "event", "-f"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except OSError as e:
            self._record({"kind": "note", "source": "watcher",
                          "detail": f"could not start `iw event` ({e}) — "
                                    "kernel 802.11 events not recorded"})
            self._iw_proc = None
            return
        threading.Thread(target=self._iw_reader, name="nf-iw-events",
                         daemon=True).start()

    def _iw_reader(self):
        proc = self._iw_proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            if self._stop.is_set():
                break
            line = line.strip()
            if not line:
                continue
            rec = parse_iw_event_line(line)
            if rec is not None:
                rec["source"] = "iw"
                self._iw_queue.put(rec)

    def _maybe_restart_iw(self, now: float):
        """Bounded respawn of the iw event source (SnifferKeeper pattern)."""
        if self._iw_restarts >= _MAX_IW_RESTARTS:
            if self._iw_restarts == _MAX_IW_RESTARTS:
                self._iw_restarts += 1
                self._record({"kind": "note", "source": "watcher",
                              "detail": "iw event source gave up after "
                                        f"{_MAX_IW_RESTARTS} restarts"})
            self._iw_proc = None
            return
        if now - self._iw_last_restart < 60:
            return
        self._iw_last_restart = now
        self._iw_restarts += 1
        self._record({"kind": "note", "source": "watcher",
                      "detail": f"iw event source exited; restarting "
                                f"(attempt {self._iw_restarts}/"
                                f"{_MAX_IW_RESTARTS})"})
        self._iw_proc = None
        self._start_iw_events()

    def _drain_iw_queue(self):
        while True:
            try:
                rec = self._iw_queue.get_nowait()
            except queue.Empty:
                return
            self._record(rec)

    # -- journal source ------------------------------------------------------

    def _journal_poll(self, now: float):
        if self._journal_gave_up or not capabilities.have("journalctl"):
            return
        since = max(0.0, self._journal_watermark - 1.0)
        out = self._run(["journalctl", "-b", "-t", "wpa_supplicant",
                         "-u", "NetworkManager", "--since", f"@{since:.6f}",
                         "-o", "short-unix", "--no-pager"])
        if out is None:
            self._journal_failures += 1
            if self._journal_failures >= _MAX_JOURNAL_FAILURES:
                self._journal_gave_up = True
                self._record({"kind": "note", "source": "watcher",
                              "detail": "journal reads keep failing — "
                                        "supplicant reason codes no longer "
                                        "recorded"})
            return
        self._journal_failures = 0
        for line in out.splitlines():
            parsed = parse_journal_line(line)
            if parsed is None:
                continue
            ts, msg = parsed
            if ts <= self._journal_watermark:
                continue   # already ingested (overlap window)
            self._journal_watermark = ts
            d = parse_supplicant_disconnect(msg)
            if d is not None:
                d["ts"] = ts
                self._supplicant_obs.append(d)
                self._supplicant_obs = self._supplicant_obs[-_MAX_SUPPLICANT_OBS:]
                self._record({"kind": "deauth", "source": "journal", "ts": ts,
                              "bssid": d["bssid"], "reason": d["reason"],
                              "locally_generated": d["locally_generated"],
                              "detail": msg.strip()[:200],
                              "detail_note": "mac_in_use reflects observation "
                                             "time, not event time (backfill)"})
            elif any(k in msg for k in _JOURNAL_KEYWORDS):
                self._record({"kind": self._journal_kind(msg),
                              "source": "journal", "ts": ts,
                              "detail": msg.strip()[:200]})
        self._check_deauth_burst(now)

    @staticmethod
    def _journal_kind(msg: str) -> str:
        if "CTRL-EVENT-ASSOC" in msg:
            return "assoc"
        if "Association request" in msg:
            return "assoc_failed" if "fail" in msg.lower() else "assoc_attempt"
        if "Trying to associate" in msg:
            return "assoc_attempt"
        if "Authentication rejected" in msg or "auth fails" in msg:
            return "auth_rejected"
        if "Authentication with" in msg:
            return "auth_status"
        if "activation of connection" in msg:
            return "activation"
        if "CTRL-EVENT-DISCONNECTED" in msg:
            return "deauth"
        return "journal_note"

    def _check_deauth_burst(self, now: float):
        ev = classify_deauth_signature(
            self._supplicant_obs, now,
            int(cfg("wifi", "deauth_threshold", 4)),
            float(cfg("wifi", "deauth_window_s", 180)))
        if ev and now - self._last_pattern.get("deauth_burst", 0.0) >= 600:
            self._last_pattern["deauth_burst"] = now
            self._record({"kind": "deauth_burst", "source": "pattern",
                          "detail": ev["summary"], **ev["evidence"]})

    # -- state poller --------------------------------------------------------

    def _detect_iface(self) -> Optional[str]:
        out = self._run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"])
        if out:
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 3 and parts[1] == "wifi":
                    return parts[0]
        out = self._run(["iw", "dev"])
        if out:
            m = re.search(r"Interface\s+(\S+)", out)
            if m:
                return m.group(1)
        return None

    def _state_poll(self, now: float):
        iface = self._detect_iface()
        if iface != self._iface:
            self._iface = iface
            self._last_state_key = None
            self._gw_history = []
        if not iface:
            # note once per absence (first poll included), not per poll
            if not self._no_iface_noted:
                self._no_iface_noted = True
                self._record({"kind": "note", "source": "watcher",
                              "detail": "no wireless interface present "
                                        "(driver not loaded / rfkill)"})
            return
        if self._no_iface_noted or self._last_state_key is None:
            self._no_iface_noted = False
            self._record({"kind": "note", "source": "watcher",
                          "detail": f"watching wireless interface {iface}"})
        mac = self._probe_mac(iface)
        mac_changed = bool(mac and mac != self._mac_in_use)
        if mac_changed:
            self._record({"kind": "note", "source": "watcher",
                          "detail": f"interface MAC is now {mac}"
                                    + (f" (was {self._mac_in_use})"
                                       if self._mac_in_use else "")})
            self._mac_in_use = mac

        link: Dict[str, Any] = {}
        iw_out = self._run(["iw", "dev", iface, "link"])
        if iw_out is not None:
            link = parse_iw_link_ext(iw_out)
        ip_addr = None
        ip_out = self._run(["ip", "-4", "addr", "show", iface])
        if ip_out:
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", ip_out)
            if m:
                ip_addr = m.group(1)
        gw_ip = None
        route_out = self._run(["ip", "route"])
        if route_out:
            gw = parse_default_route(route_out)
            if gw and gw.get("interface") == iface:
                gw_ip = gw.get("gateway")
        gw_mac = None
        if gw_ip:
            neigh = self._run(["ip", "neigh"])
            if neigh:
                for row in parse_neigh_output(neigh):
                    if row["ip"] == gw_ip and row["dev"] == iface \
                            and row["state"] != "FAILED":
                        gw_mac = row["mac"]
                        break
        gw_ok = False
        if gw_ip and link.get("connected") and ip_addr:
            gw_ok = self._run(["ping", "-c", "1", "-W", "1", gw_ip]) is not None
        band = band_from_freq(link.get("freq"))

        key = (bool(link.get("connected")), link.get("bssid"), ip_addr,
               gw_ip, gw_mac, band, mac)
        heartbeat = float(cfg("wifi", "watcher_heartbeat_s", 60))
        if key != self._last_state_key or now - self._last_heartbeat >= heartbeat:
            self._last_state_key = key
            self._last_heartbeat = now
            self._record({"kind": "state", "source": "poll", "iface": iface,
                          "associated": bool(link.get("connected")),
                          "ssid": link.get("ssid"), "bssid": link.get("bssid"),
                          "rssi": link.get("rssi"), "freq": link.get("freq"),
                          "band": band, "ip": ip_addr, "gw_ip": gw_ip,
                          "gw_mac": gw_mac, "gw_ok": gw_ok,
                          "iface_mac": mac})

        if link.get("connected") and gw_ip and gw_mac:
            self._gw_history.append({"t": now, "gw_ip": gw_ip, "gw_mac": gw_mac})
            self._gw_history = self._gw_history[-40:]
            self._check_gateway_flap(now)
        elif not link.get("connected"):
            self._gw_history = []

    def _probe_mac(self, iface: str) -> Optional[str]:
        out = self._run(["ip", "link", "show", iface])
        return parse_ip_link_mac(out) if out else None

    def _check_gateway_flap(self, now: float):
        window = 120.0
        recent = [g for g in self._gw_history if now - g["t"] <= window]
        macs = {g["gw_mac"] for g in recent}
        if len(macs) >= 2 and now - self._last_pattern.get("gateway_flap", 0.0) >= 600:
            self._last_pattern["gateway_flap"] = now
            self._record({
                "kind": "gateway_flap", "source": "pattern",
                "detail": "gateway MAC flapped within "
                          f"{window:.0f}s while associated — ARP-spoof "
                          "signature (NetCut-class) or a router HA pair; "
                          "the engine's arp guard holds the alerting role",
                "gateway_macs": sorted(macs)})

    # -- record sink ----------------------------------------------------------

    def _record(self, rec: Dict[str, Any]) -> None:
        """Annotate + persist. mac_in_use reflects WATCHER observation
        time; backfilled journal records carry their own ts."""
        if self._mac_in_use and "mac_in_use" not in rec:
            rec["mac_in_use"] = self._mac_in_use
        if self._iface and not rec.get("iface"):
            rec["iface"] = self._iface
        self.log.append(rec)

    def status(self) -> Dict[str, Any]:
        now = time.time()
        recent = evidence_query(self.log.path, since=now - 3600)
        s = summarize_window(recent)
        last_state = next((r for r in reversed(recent)
                           if r.get("kind") == "state"), {})
        return {
            "running": self.started_at is not None and not self._stop.is_set(),
            "started_at": self.started_at,
            "records_written": self.log.records_written,
            "interface": self._iface,
            "mac_in_use": self._mac_in_use,
            "last_state": last_state,
            "last_hour": s,
        }


# ---------------------------------------------------------------------------
# Entry point (systemd netfend-wifi-watch.service / manual)
# ---------------------------------------------------------------------------

def run_watcher(path: Path = None) -> int:
    """Foreground watcher run. Returns an exit code (P-41 style: 1 when
    another watcher already holds the lock)."""
    fd, conflict = acquire_lock("/run/netfend.wifi-watch.lock")
    if conflict is not None:
        print(f"[netfend] Another link watcher is already running"
              + (f" (pid {conflict})" if conflict.isdigit() else "") + ".")
        print("       It is the systemd service 'netfend-wifi-watch' if enabled:")
        print("         watch it : systemctl status netfend-wifi-watch")
        print("         stop it  : sudo systemctl stop netfend-wifi-watch")
        return 1
    # fd stays open for the process lifetime; the kernel releases it on exit

    watcher = LinkWatcher(path)

    import signal

    def _handler(signum, frame):
        watcher.stop()

    try:
        signal.signal(signal.SIGTERM, _handler)
        signal.signal(signal.SIGINT, _handler)
    except (ValueError, OSError):
        pass

    log_info("link watcher active (boot-early evidence recorder)")
    print("[netfend] link watcher running — Ctrl+C to stop "
          "(evidence log: link-evidence.jsonl)")
    try:
        return watcher.run_forever()
    except KeyboardInterrupt:
        watcher.stop()
        return 0
