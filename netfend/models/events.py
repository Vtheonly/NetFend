"""SecurityEvent + EventStore — the single event backbone (ADR-005).

Every guard detection flows through here. Consumers:
- CLI (`--events`)
- log file (WARN+ mirrored)
- dashboard `/api/events`, `/api/security`
- JSONL persistence with size-based rotation (bounded disk use)

Design notes:
- Events carry severity AND confidence with an explicit
  confirmed/suspected/unverified vocabulary (owner requirement: distinguish
  confirmed events from suspected anomalies).
- The store is thread-safe; emit() is cheap (lock + deque append + buffered
  file write). Persistence is size-rotated, NOT per-event fsync.
- Deduplication (P-21, live report 2026-10-15): identical (kind, summary)
  events inside `event_dedup_window_s` (default 10 s) collapse into the
  FIRST occurrence with a `repeat_count` — a flapping detection produces
  one event with "xN" in the UI instead of a hundred identical rows.
  Dedup updates live in the in-memory ring only; the JSONL keeps the
  first occurrence per burst.
- Restart continuity: the ring is seeded from the JSONL tail on startup,
  so `netfend --events` and the dashboard show recent history instead of
  starting empty (the CLI constructed a fresh EventStore and silently
  showed nothing — pre-existing bug found while fixing P-21).
"""
import json
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from netfend.utils.config import (
    EVENTS_FILE, cfg, SEV_INFO, SEV_NOTICE, SEV_WARNING, SEV_CRITICAL,
    CONFIRMED, SUSPECTED, UNVERIFIED,
)

_SEV_ORDER = {SEV_INFO: 0, SEV_NOTICE: 1, SEV_WARNING: 2, SEV_CRITICAL: 3}

# hard cap on the dedup map so a pathological variety of summaries cannot
# grow it without bound (entries expire with the window anyway)
_DEDUP_MAP_MAX = 512


@dataclass
class SecurityEvent:
    kind: str                    # e.g. "arp.gateway_spoof"
    severity: str                # info | notice | warning | critical
    confidence: str              # confirmed | suspected | unverified
    summary: str                 # one-line human explanation
    source: str = "engine"       # emitting component
    evidence: Dict[str, Any] = field(default_factory=dict)
    interface: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    repeat_count: int = 0        # P-21: identical events inside the dedup window

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SecurityEvent":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


class EventStore:
    """Thread-safe ring buffer + rotating JSONL persistence + dedup."""

    def __init__(self, path: Path = None, ring_size: int = None,
                 file_max_bytes: int = None, dedup_window_s: float = None,
                 load_history: bool = True):
        self.path = Path(path) if path else EVENTS_FILE
        self.ring: Deque[SecurityEvent] = deque(
            maxlen=ring_size or cfg("general", "events_ring_size", 2000)
        )
        self.file_max_bytes = file_max_bytes or cfg("general", "events_file_max_bytes", 2_000_000)
        self.dedup_window = (dedup_window_s if dedup_window_s is not None
                             else cfg("general", "event_dedup_window_s", 10))
        self._lock = threading.Lock()
        self._fh = None
        self._bytes_written = 0
        self._dedup: Dict[tuple, SecurityEvent] = {}
        if load_history:
            self._load_tail()
        self._open()

    # -- persistence -------------------------------------------------------
    def _open(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.path, "a", encoding="utf-8")
            self._fh.seek(0, os.SEEK_END)
            self._bytes_written = self._fh.tell()
        except OSError:
            self._fh = None  # persistence unavailable; in-memory still works

    def _load_tail(self):
        """Seed the ring from the persisted JSONL (restart continuity)."""
        try:
            if not self.path.exists():
                return
            with open(self.path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            loaded: List[SecurityEvent] = []
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    loaded.append(SecurityEvent.from_dict(json.loads(line)))
                except (json.JSONDecodeError, TypeError, ValueError):
                    continue
                if len(loaded) >= self.ring.maxlen:
                    break
            self.ring.extend(reversed(loaded))
        except OSError:
            pass  # unreadable history must never block the store

    def _rotate_if_needed(self):
        if self._fh is None:
            return
        if self._bytes_written >= self.file_max_bytes:
            try:
                self._fh.close()
                rotated = self.path.with_suffix(".jsonl.1")
                if rotated.exists():
                    rotated.unlink()
                self.path.rename(rotated)
                self._fh = open(self.path, "a", encoding="utf-8")
                self._bytes_written = 0
            except OSError:
                self._fh = None

    # -- public API ---------------------------------------------------------
    def emit(self, event: SecurityEvent) -> SecurityEvent:
        """Append an event, or fold it into an identical recent event.

        Identical (kind, summary) within the dedup window increments the
        existing event's repeat_count instead of creating a new row. The
        persisted JSONL only records the first occurrence of a burst.
        """
        with self._lock:
            key = (event.kind, event.summary)
            now = event.timestamp or time.time()
            prev = self._dedup.get(key)
            if prev is not None and (now - prev.timestamp) < self.dedup_window:
                prev.repeat_count += 1
                return prev
            self.ring.append(event)
            self._dedup[key] = event
            if len(self._dedup) > _DEDUP_MAP_MAX:
                self._prune_dedup(now)
            if self._fh is not None:
                try:
                    line = json.dumps(event.to_dict(), default=str) + "\n"
                    self._fh.write(line)
                    self._fh.flush()
                    self._bytes_written += len(line.encode("utf-8"))
                    self._rotate_if_needed()
                except OSError:
                    self._fh = None
        return event

    def _prune_dedup(self, now: float) -> None:
        """Drop dedup entries whose window expired (caller holds lock)."""
        expired = [k for k, ev in self._dedup.items()
                   if (now - ev.timestamp) >= self.dedup_window]
        for k in expired:
            del self._dedup[k]

    def emit_simple(self, kind: str, severity: str, confidence: str,
                    summary: str, source: str = "engine", **evidence) -> SecurityEvent:
        return self.emit(SecurityEvent(
            kind=kind, severity=severity, confidence=confidence,
            summary=summary, source=source, evidence=evidence or {},
        ))

    def query(self, limit: int = 100, min_severity: str = None,
              kind_prefix: str = None, interface: str = None,
              since: float = None) -> List[Dict[str, Any]]:
        """Newest-first filtered view (dashboard/CLI)."""
        min_ord = _SEV_ORDER.get(min_severity, 0) if min_severity else 0
        out: List[Dict[str, Any]] = []
        with self._lock:
            snapshot = list(self.ring)
        for ev in reversed(snapshot):
            if len(out) >= limit:
                break
            if _SEV_ORDER.get(ev.severity, 0) < min_ord:
                continue
            if kind_prefix and not ev.kind.startswith(kind_prefix):
                continue
            if interface and ev.interface and ev.interface != interface:
                continue
            if since and ev.timestamp < since:
                continue
            out.append(ev.to_dict())
        return out

    def count_since(self, since: float, kind_prefix: str = None) -> int:
        with self._lock:
            snapshot = list(self.ring)
        n = 0
        for ev in snapshot:
            if ev.timestamp >= since and (kind_prefix is None or ev.kind.startswith(kind_prefix)):
                n += 1
        return n

    def close(self):
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None
