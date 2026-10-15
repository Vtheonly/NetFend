"""MetricsCollector — throughput, packet rates, latency, health verdict.

Sources (all cheap, no polling storms):
- /proc/net/dev deltas  -> rx/tx bytes+packets per second (2 s cadence)
- gateway `ping -c1`    -> RTT + loss (10 s cadence, single probe)
- /proc/self or psutil  -> engine CPU + memory

`health_verdict()` produces the "why is my internet slow" explanation
from measured evidence only (owner requirement: real measurements, no
simulated values).
"""
import subprocess
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from netfend.models.events import EventStore
from netfend.services.network_manager import parse_proc_net_dev
from netfend.utils import capabilities
from netfend.utils.config import cfg
from netfend.utils.logging import log_warn


def compute_rates(prev: Dict[str, int], cur: Dict[str, int],
                  dt: float) -> Dict[str, float]:
    """Pure: rx/tx B/s + pps between two /proc/net/dev snapshots."""
    if dt <= 0:
        return {"rx_bps": 0.0, "tx_bps": 0.0, "rx_pps": 0.0, "tx_pps": 0.0}
    return {
        "rx_bps": max(0, cur["rx_bytes"] - prev["rx_bytes"]) / dt,
        "tx_bps": max(0, cur["tx_bytes"] - prev["tx_bytes"]) / dt,
        "rx_pps": max(0, cur["rx_packets"] - prev["rx_packets"]) / dt,
        "tx_pps": max(0, cur["tx_packets"] - prev["tx_packets"]) / dt,
    }


def health_verdict(v: Dict[str, Any]) -> Dict[str, Any]:
    """Pure: combine measurements into a status + explanation.

    v: {loss_pct, rtt_ms, dns_ok, gw_ok, rx_bps, tx_bps, weak_signal}
    """
    loss = v.get("loss_pct") or 0.0
    rtt = v.get("rtt_ms")
    dns_ok = v.get("dns_ok")
    gw_ok = v.get("gw_ok")
    weak = v.get("weak_signal", False)
    reasons: List[str] = []
    status = "healthy"

    if gw_ok is False:
        status = "down"
        reasons.append("gateway does not answer ping (network/route down)")
    elif loss >= 25:
        status = "degraded"
        reasons.append(f"{loss:.0f}% ping loss to gateway (Wi-Fi interference, congestion, or flooding)")
    elif rtt is not None and rtt > 200:
        status = "degraded"
        reasons.append(f"gateway latency {rtt:.0f} ms (congested link or interference)")
    if dns_ok is False and status != "down":
        reasons.append("DNS resolution failing (resolver problem — browsing will fail even though the link is up)")
        if status == "healthy":
            status = "degraded"
    if weak and status == "healthy":
        reasons.append("weak Wi-Fi signal")
    if not reasons:
        reasons.append("latency, loss, DNS and gateway reachability all nominal")
    return {"status": status,
            "explanation": "; ".join(reasons) + "."}


class MetricsCollector:
    def __init__(self, nm, events: EventStore):
        self.nm = nm
        self.events = events
        self._stop = threading.Event()
        self._sample_thread: Optional[threading.Thread] = None
        self._ping_thread: Optional[threading.Thread] = None
        self._last_counters: Optional[Dict[str, Dict[str, int]]] = None
        self._last_ts: Optional[float] = None
        self.history: Deque[Dict[str, Any]] = deque(
            maxlen=cfg("metrics", "history_points", 600))
        self.rtt_history: Deque[float] = deque(maxlen=30)
        self.ping_results: Deque[bool] = deque(maxlen=30)
        self.current: Dict[str, Any] = {"rx_bps": 0.0, "tx_bps": 0.0,
                                        "rx_pps": 0.0, "tx_pps": 0.0}
        self.process_cpu: float = 0.0
        self.process_mem_mb: float = 0.0
        self._proc = None
        self._last_cpu_sample = None

    # -- /proc sampling -------------------------------------------------------
    def _read_proc_net_dev(self) -> Optional[Dict[str, Dict[str, int]]]:
        try:
            with open("/proc/net/dev") as f:
                return parse_proc_net_dev(f.read())
        except OSError:
            return None

    def _sample_loop(self):
        interval = cfg("metrics", "sample_interval_s", 2)
        while not self._stop.wait(interval):
            counters = self._read_proc_net_dev()
            now = time.time()
            iface = self.nm.snapshot()["interface"]
            if counters is None or not iface:
                continue
            cur = counters.get(iface)
            if not cur:
                continue
            if self._last_counters and self._last_ts and iface in self._last_counters:
                dt = now - self._last_ts
                rates = compute_rates(self._last_counters[iface], cur, dt)
                self.current.update(rates)
                self.current["ts"] = now
                self.history.append({
                    "ts": now,
                    "rx_bps": round(rates["rx_bps"], 1),
                    "tx_bps": round(rates["tx_bps"], 1),
                    "rx_pps": round(rates["rx_pps"], 1),
                    "tx_pps": round(rates["tx_pps"], 1),
                })
            self._last_counters = counters
            self._last_ts = now
            self._sample_process()

    def _sample_process(self):
        try:
            if capabilities.have("psutil"):
                import psutil
                if self._proc is None:
                    self._proc = psutil.Process()
                self.process_cpu = self._proc.cpu_percent(interval=None)
                self.process_mem_mb = self._proc.memory_info().rss / (1024 * 1024)
            else:
                # /proc fallback
                with open("/proc/self/stat") as f:
                    parts = f.read().split()
                utime = int(parts[13]) + int(parts[14])
                if self._last_cpu_sample is not None:
                    dticks = utime - self._last_cpu_sample
                    self.process_cpu = min(100.0, dticks / (os_clk() * cfg("metrics", "sample_interval_s", 2) / 100.0))
                self._last_cpu_sample = utime
                with open("/proc/self/status") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            self.process_mem_mb = int(line.split()[1]) / 1024
                            break
        except (OSError, ValueError, ImportError):
            pass

    # -- latency / loss ---------------------------------------------------------
    def _ping_loop(self):
        interval = cfg("metrics", "ping_interval_s", 10)
        timeout = cfg("metrics", "ping_timeout_s", 1)
        while not self._stop.wait(interval):
            gw = self.nm.snapshot()["gateway_ip"]
            if not gw:
                continue
            ok, rtt = self._ping(gw, timeout)
            self.ping_results.append(ok)
            if ok and rtt is not None:
                self.rtt_history.append(rtt)
            self.current["gw_ok"] = ok
            self.current["rtt_ms"] = round(rtt, 1) if rtt else None

    @staticmethod
    def _ping(target: str, timeout: float):
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", str(max(1, int(timeout))), target],
                capture_output=True, text=True, timeout=timeout + 3)
            if r.returncode != 0:
                return False, None
            import re
            m = re.search(r"time=([\d.]+)", r.stdout)
            return True, float(m.group(1)) if m else None
        except (OSError, subprocess.SubprocessError):
            return None, None  # unknown (ping missing etc.)

    # -- lifecycle -----------------------------------------------------------------
    def start(self) -> bool:
        if not cfg("metrics", "enabled", True):
            return False
        if self._read_proc_net_dev() is None:
            self.events.emit_simple(
                "metrics.unavailable", "warning", "unverified",
                "Throughput metrics unavailable (/proc/net/dev not readable)",
                source="metrics")
            return False
        self._sample_thread = threading.Thread(
            target=self._sample_loop, name="nf-metrics", daemon=True)
        self._sample_thread.start()
        self._ping_thread = threading.Thread(
            target=self._ping_loop, name="nf-ping", daemon=True)
        self._ping_thread.start()
        return True

    def snapshot(self) -> Dict[str, Any]:
        loss_pct = 0.0
        if self.ping_results:
            fails = sum(1 for ok in self.ping_results if ok is False)
            total = sum(1 for ok in self.ping_results if ok is not None)
            loss_pct = (fails / total * 100) if total else 0.0
        avg_rtt = (sum(self.rtt_history) / len(self.rtt_history)
                   if self.rtt_history else None)
        return {
            "throughput": {
                "rx_bps": round(self.current.get("rx_bps", 0.0), 1),
                "tx_bps": round(self.current.get("tx_bps", 0.0), 1),
                "rx_pps": round(self.current.get("rx_pps", 0.0), 1),
                "tx_pps": round(self.current.get("tx_pps", 0.0), 1),
            },
            "latency": {
                "rtt_ms": self.current.get("rtt_ms"),
                "avg_rtt_ms": round(avg_rtt, 1) if avg_rtt else None,
                "loss_pct": round(loss_pct, 1),
                "gw_ok": self.current.get("gw_ok"),
            },
            "engine": {
                "cpu_pct": round(self.process_cpu, 1),
                "mem_mb": round(self.process_mem_mb, 1),
            },
            "history": list(self.history)[-150:],
        }

    def verdict(self, dns_ok: Optional[bool], weak_signal: bool) -> Dict[str, Any]:
        s = self.snapshot()
        return health_verdict({
            "loss_pct": s["latency"]["loss_pct"],
            "rtt_ms": s["latency"]["rtt_ms"],
            "dns_ok": dns_ok,
            "gw_ok": s["latency"]["gw_ok"],
            "rx_bps": s["throughput"]["rx_bps"],
            "tx_bps": s["throughput"]["tx_bps"],
            "weak_signal": weak_signal,
        })

    def stop(self):
        self._stop.set()
        for t in (self._sample_thread, self._ping_thread):
            if t:
                t.join(timeout=2)


def os_clk() -> float:
    try:
        with open("/proc/self/stat") as f:
            # fields 1-2 overwritten; use clk_tck via os.sysconf
            pass
    except OSError:
        pass
    import os
    try:
        return float(os.sysconf("SC_CLK_TCK"))
    except (ValueError, OSError, AttributeError):
        return 100.0
