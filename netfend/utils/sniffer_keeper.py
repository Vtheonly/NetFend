"""SnifferKeeper — keep guard sniffers alive across link flaps (P-42).

Live report 2026-10-16: a brief Wi-Fi link flap closed every guard
socket (Scapy logged ``WARNING: Socket <L2ListenSocket ...> failed with
'[Errno 100] Network is down'. It was closed.``) and the ARP/DHCP/IPv6
guards stayed blind until the engine was restarted — during exactly
the reconnect window where attacks (gateway re-poisoning, rogue DHCP,
rogue RA) are most likely.

Each guarded sniffer is now supervised: a daemon thread checks
liveness every ``CHECK_INTERVAL`` seconds and, when the sniff loop has
died, rebuilds the sniffer bound to the CURRENT interface from the
network snapshot (roaming may have changed it).

Bounded: after ``MAX_CONSECUTIVE_RESTARTS`` restarts in a row the
keeper gives up and emits one critical event — a link that flaps
forever should not spin a restart loop. One healthy tick resets the
counter.

Stop-ordering contract: guards MUST call ``keeper.stop()`` BEFORE
stopping their sniffer, so the keeper can never resurrect a sniffer
the guard is shutting down.
"""
import threading
from typing import Any, Callable, Dict, Optional

from netfend.utils.logging import log_info, log_warn

CHECK_INTERVAL = 10.0
MAX_CONSECUTIVE_RESTARTS = 6

# check_and_restore() outcomes
ALIVE = "alive"          # sniffer loop healthy
RESTORED = "restored"    # rebuilt + started
DEFERRED = "deferred"    # dead, but link/identity unknown — retry next tick
FAILED = "failed"        # restart attempt raised


class SnifferKeeper:
    """Supervise one AsyncSniffer-style object.

    ``get``    () -> sniffer | None   (current sniffer, None = none started)
    ``build``  (iface) -> sniffer     (fresh, bound to the given interface)
    ``set_``   (sniffer) -> None      (store the replacement)
    """

    def __init__(self, events, nm, source: str,
                 get: Callable[[], Any],
                 build: Callable[[str], Any],
                 set_: Callable[[Any], None]):
        self.events = events
        self.nm = nm
        self.source = source
        self._get = get
        self._build = build
        self._set = set_
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._restarts = 0
        self._restarts_pending = 0
        self.gave_up = False

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._supervise, name=f"nf-keeper-{self.source}",
            daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Must be called BEFORE the guard stops its sniffer."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    # -- supervision ---------------------------------------------------------
    def _alive(self) -> bool:
        s = self._get()
        if s is None:
            return True  # nothing to supervise (never started / stopped)
        t = getattr(s, "thread", None)
        return t is not None and t.is_alive()

    def check_and_restore(self) -> str:
        """Rebuild the sniffer if its loop died. Never raises."""
        if self._stop.is_set():
            return ALIVE  # shutting down — never resurrect here
        try:
            if self._alive():
                return ALIVE
            snap = self.nm.snapshot()
            iface = snap.get("interface")
            if not iface or not snap.get("my_ip"):
                # link down / identity unknown — retry on a later tick
                return DEFERRED
            old = self._get()
            if old is not None:
                try:
                    old.stop()
                except Exception:
                    pass
            fresh = self._build(iface)
            fresh.start()
        except Exception as e:  # build/start failure — bounded retries
            log_warn(f"{self.source} sniffer restart failed: {e}")
            return FAILED
        self._set(fresh)
        self._restarts_pending = (self._restarts or 0) + 1
        log_info(f"{self.source} guard sniffer restarted "
                 f"(socket had failed; now on {iface})")
        try:
            self.events.emit_simple(
                f"{self.source}.sniffer_restarted", "warning", "confirmed",
                f"{self.source} guard sniffer socket had failed; "
                f"restarted on {iface} (restart #{self._restarts_pending})",
                source=self.source, interface=iface,
                restarts=self._restarts_pending)
        except Exception:
            pass
        return RESTORED

    def _note(self, outcome: str) -> bool:
        """Track consecutive restarts; False when the keeper gives up."""
        if outcome == ALIVE:
            self._restarts = 0
        elif outcome == RESTORED:
            self._restarts += 1
            if self._restarts >= MAX_CONSECUTIVE_RESTARTS:
                self.gave_up = True
                log_warn(f"{self.source} sniffer keeps dying "
                         f"({self._restarts} restarts) — supervision giving up")
                try:
                    self.events.emit_simple(
                        f"{self.source}.sniffer_gave_up", "critical", "confirmed",
                        f"{self.source} guard sniffer died {self._restarts} times "
                        f"in a row; supervision stopped (interface flapping "
                        f"persistently or driver fault — check 'iw dev' / dmesg)",
                        source=self.source, restarts=self._restarts)
                except Exception:
                    pass
                return False
        return True

    def _supervise(self) -> None:
        while not self._stop.wait(CHECK_INTERVAL):
            try:
                if not self._note(self.check_and_restore()):
                    return
            except Exception:  # the keeper thread itself must never die
                pass
