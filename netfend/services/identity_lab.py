"""IdentityLab — controlled network-identity A/B experiment (P-44).

Question being answered (owner, 2026-10-16): is the blocking tied to
THIS device's usual identity (MAC / hostname) or does it follow any
unknown device? The router cannot help — old hardware, WPA2-only, no
802.11w/PMF, and the passphrase must stay short for the family — so
the only clean discriminator left is on the client: connect with the
real identity, connect with a randomized identity, compare outcomes
under identical conditions.

This is a diagnostic experiment on the owner's OWN machine using a
privacy feature every modern OS ships as a checkbox (per-network MAC
randomization). It is NOT an evasion tool: it never touches the
router, never sends a packet whose purpose is to affect another host
(ADR-001), and its entire purpose is measurement with restoration.

Experiment contract (the safety rails, in order):
  1. BACKUP the profile's identity settings to disk BEFORE anything is
     changed. The file is the recovery point; a crash cannot lose it,
     and a later run auto-heals a leftover backup BEFORE starting.
  2. For each phase: apply identity -> write a phase marker into the
     link evidence log (link_watcher.py) -> reconnect -> poll state ->
     classify outcome -> dwell and keep observing.
  3. ALWAYS restore in `finally` — Ctrl+C, nmcli failure, any error.
     The backup file survives until a VERIFIED restore deletes it.
  4. Report: per-phase table + evidence timeline + verdict from the
     interpretation matrix, saved under DATA_DIR/abtest/.

Verdict interpretation matrix (the whole point):
  real BAD  + random OK   -> identity-targeted: the block follows the
                             usual MAC/hostname (static target list)
  real BAD  + random BAD  -> not identity-static: attacker re-learns
                             unknown devices (whitelist policy) or the
                             block is not identity-keyed
  real OK   + random OK   -> no active blocking during this run (the
                             experiment must be repeated during an
                             incident to mean anything)
  real OK   + random BAD  -> unknown-MAC rejection: check the router
                             for MAC whitelist / parental controls
  mixed within a condition -> inconclusive: more cycles needed
"""
import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from netfend.services.link_watcher import (
    append_marker,
    band_from_freq,
    evidence_query,
    parse_iw_link_ext,
    parse_ip_link_mac,
    summarize_window,
)
from netfend.services.network_manager import parse_default_route
from netfend.utils import config as config_mod
from netfend.utils.config import cfg
from netfend.utils.logging import log_info, log_warn

_TIMEOUT = 6

# NM connection-profile properties used as "identity"
MAC_PROP = "wifi.cloned-mac-address"
BAND_PROP = "wifi.band"
ANON_PROPS = ("ipv4.dhcp-send-hostname", "ipv6.dhcp-send-hostname")
# Documented NM defaults for UNSET properties. nmcli -g prints an empty
# string for unset; restoring "" is invalid input, so the backup
# normalizes empties to these concrete values (behaviorally identical
# to unset — see AGENTS.md P-44 trap).
_NM_DEFAULTS = {
    MAC_PROP: "preserve",
    BAND_PROP: "any",
    "ipv4.dhcp-send-hostname": "yes",
    "ipv6.dhcp-send-hostname": "yes",
}

OUTCOME_BLOCKED = ("rejected", "assoc_no_dhcp")


class ProbeExhausted(Exception):
    """Test-mode signal: the injected canned probe list ran out."""


def _run(cmd: List[str], timeout: int = _TIMEOUT) -> Optional[str]:
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable)
# ---------------------------------------------------------------------------

def random_local_mac(rng: Callable[[], Any] = None) -> str:
    """Locally-administered unicast MAC: octet 0 bit1 set (locally
    administered), bit0 clear (unicast). Avoids colliding with any real
    vendor OUI by construction. `rng` injectable for deterministic tests
    (returns an iterable of 6 byte-sized ints)."""
    if rng is None:
        import secrets
        raw = secrets.token_bytes(6)
    else:
        raw = bytes(rng())
    b = bytearray(raw)
    b[0] = (b[0] | 0x02) & 0xFE
    return ":".join(f"{x:02x}" for x in b)


def parse_nmcli_connections(output: str) -> List[Dict[str, str]]:
    """Parse `nmcli -t -f NAME,TYPE,DEVICE,ACTIVE connection show`.

    Terse mode escapes literal colons inside values as '\\:' — split on
    UNescaped colons only.
    """
    rows: List[Dict[str, str]] = []
    for line in output.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) >= 4 and parts[1] == "802-11-wireless":
            rows.append({
                "name": parts[0].replace("\\:", ":"),
                "device": parts[2].replace("\\:", ":"),
                "active": parts[3] == "yes",
            })
    return rows


def select_profile(connections: List[Dict[str, str]],
                   prefer_name: str = None,
                   prefer_ssid: str = None
                   ) -> Tuple[Optional[str], str]:
    """Pick the experiment's NM profile. Active wifi profile first (the
    blocked case has none — then the only wifi profile; more than one
    needs an explicit pin). Returns (profile_name_or_None, how)."""
    if prefer_name:
        for c in connections:
            if c["name"] == prefer_name:
                return c["name"], "named"
    if prefer_ssid:
        matches = [c for c in connections
                   if prefer_ssid.lower() in c["name"].lower()]
        if len(matches) == 1:
            return matches[0]["name"], "ssid-substring"
    active = [c for c in connections if c.get("active")]
    if len(active) == 1:
        return active[0]["name"], "active"
    if len(connections) == 1:
        return connections[0]["name"], "only-wifi-profile"
    return None, "ambiguous-or-none"


def classify_phase(polls: List[Dict[str, Any]],
                   records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Classify one phase's connection outcome.

    Outcomes (ordered worst to best):
      rejected           never associated (auth/assoc refused or ignored)
      assoc_no_dhcp      associated but never got an IPv4 address
      connected_no_gw    associated + IP, gateway never answered (L3 cut)
      connected_lost     was fully connected, association gone at phase end
      connected_unstable connected at end but incoming deauths observed
      connected_ok       connected at end, clean window
    """
    summary = summarize_window(records)
    if not polls:
        return {"outcome": "no_data", "summary": summary}
    assoc = [p for p in polls if p.get("associated")]
    with_ip = [p for p in polls if p.get("ip")]
    with_gw = [p for p in polls if p.get("gw_ok")]
    end = polls[-1]
    end_connected = bool(end.get("associated") and end.get("ip"))
    if not assoc:
        outcome = "rejected"
    elif not with_ip:
        outcome = "assoc_no_dhcp"
    elif not with_gw:
        outcome = "connected_no_gw"
    elif not end_connected:
        outcome = "connected_lost"
    elif summary["incoming_deauths"] > 0:
        outcome = "connected_unstable"
    else:
        outcome = "connected_ok"

    rssi_vals = [p.get("rssi") for p in polls if p.get("rssi") is not None]
    bands = sorted({p.get("band") for p in polls if p.get("band")})
    return {
        "outcome": outcome,
        "ever_associated": bool(assoc),
        "ever_ip": bool(with_ip),
        "ever_gateway": bool(with_gw),
        "end_connected": end_connected,
        "rssi_min": min(rssi_vals) if rssi_vals else None,
        "bands": bands,
        "summary": summary,
    }


def classify_verdict(phase_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Interpretation matrix: compare real-identity phases vs
    random-identity phases. See module docstring for the decision
    table and what each verdict means operationally."""
    def outcomes(kind: str) -> List[str]:
        return [p["outcome"] for p in phase_results if p.get("phase") == kind]

    real, rand = outcomes("real"), outcomes("random")
    if not real or not rand:
        return {"verdict": "incomplete", "confidence": "unverified",
                "explanation": "not enough phases completed to compare",
                "next_steps": ["re-run the experiment"]}

    all_ok = lambda lst: all(o == "connected_ok" for o in lst)
    all_bad = lambda lst: all(o != "connected_ok" for o in lst)

    if all_bad(real) and all_ok(rand):
        return {
            "verdict": "identity_targeted", "confidence": "confirmed",
            "explanation": (
                "Blocking followed your USUAL identity and a randomized "
                "identity connected cleanly: the attacker is maintaining a "
                "static target list keyed on your MAC (router-level MAC "
                "filter under attacker control, or a saved-target NetCut-"
                "class tool) — not disrupting the network."),
            "next_steps": [
                "Personal mitigation (your own device, standard privacy "
                "feature): keep a randomized MAC on this profile — "
                'nmcli connection modify "<profile>" wifi.cloned-mac-address '
                'random — and a DIFFERENT random one if this one gets '
                "targeted later.",
                "Save the evidence: sudo netfend wifi events --kind deauth "
                "(timestamps + reason codes are the reportable artifact).",
                "The router was re-compromised after the factory reset or "
                "the passphrase was re-cracked offline (17-min window fits "
                "a weak WPA2 passphrase): consider a WPA3/PMF-capable "
                "replacement, and report with evidence if this persists.",
                "Keep the engine running — its ARP-level defenses protect "
                "whatever identity you use.",
            ]}
    if all_bad(real) and all_bad(rand):
        return {
            "verdict": "not_identity_only", "confidence": "confirmed",
            "explanation": (
                "BOTH identities were blocked: the attacker's tooling "
                "re-learns unknown devices (whitelist policy: family "
                "devices allowed, unknown MACs attacked) or the block is "
                "not keyed on identity at all."),
            "next_steps": [
                "Check the router admin UI for unknown MAC-filter / "
                "parental-control entries right after an incident.",
                "Look at the deauth columns above: incoming deauths in "
                "both phases = wireless deauthing — no password change "
                "helps; only PMF/WPA3 hardware or a band change does.",
                "Try the 5 GHz band: sudo netfend wifi abtest --band a — "
                "cheap deauth tools are often 2.4 GHz-only.",
                "If assoc was refused outright in both phases, compare "
                "with a phone hotspot: that isolates the router from the "
                "radio environment.",
            ]}
    if all_ok(real) and all_ok(rand):
        return {
            "verdict": "no_active_blocking", "confidence": "confirmed",
            "explanation": (
                "Both identities worked during this run — no blocking was "
                "active. The experiment only means something when run "
                "DURING an incident."),
            "next_steps": [
                "Repeat during the next blocking episode: sudo netfend "
                "wifi abtest",
                "The watcher service records everything from boot — the "
                "next incident will be fully captured even if you run "
                "this late: systemctl status netfend-wifi-watch",
            ]}
    if all_ok(real) and all_bad(rand):
        return {
            "verdict": "unknown_mac_rejected", "confidence": "suspected",
            "explanation": (
                "Your usual identity worked but a random one was blocked — "
                "the opposite of attacker behavior. Most likely the ROUTER "
                "itself restricts unknown MACs."),
            "next_steps": [
                "Check the router for a MAC whitelist / access control / "
                "parental controls / 'block unknown devices' setting.",
                "If found and intentional, the experiment is still valid: "
                "temporarily allow unknown MACs, or add the randomized MAC "
                "used above to the allowed list, then re-run.",
            ]}
    return {
        "verdict": "inconclusive", "confidence": "unverified",
        "explanation": (
            "Outcomes varied WITHIN one condition — intermittent attacker, "
            "flaky radio, or too few cycles."),
        "next_steps": [
            "Re-run with more cycles: sudo netfend wifi abtest --cycles 4",
            "Check the RSSI column in the phase table — weak signal "
            "mimics blocking (and note the band each phase used).",
        ]}


def render_report_md(session: Dict[str, Any]) -> str:
    """Human-readable markdown report of an A/B session."""

    def iso(ts: Optional[float]) -> str:
        if not ts:
            return "-"
        try:
            return datetime.fromtimestamp(ts).astimezone().strftime(
                "%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError):
            return "-"

    lines: List[str] = []
    lines.append("# NetFend identity A/B report")
    lines.append("")
    lines.append(f"- started: {iso(session.get('started'))}  "
                 f"finished: {iso(session.get('finished'))}")
    lines.append(f"- profile: {session.get('profile')}"
                 f" (interface {session.get('iface') or 'unknown'})")
    lines.append(f"- cycles: {session.get('cycles')}, "
                 f"dwell: {session.get('dwell_s')}s per phase, "
                 f"connect timeout: {session.get('connect_timeout_s')}s")
    if session.get("band"):
        lines.append(f"- band pinned for BOTH phases (controlled "
                     f"comparison): {session['band']}")
    lines.append("")
    lines.append("## Phases")
    lines.append("| # | phase | MAC applied | outcome | incoming deauths | "
                 "assoc attempts | gateway MACs | RSSI min | band |")
    lines.append("|---|-------|-------------|---------|------------------|"
                 "----------------|--------------|----------|------|")
    for pr in session.get("phase_results", []):
        s = pr.get("summary", {})
        lines.append(
            f"| {pr.get('index', '-')} | {pr.get('phase')}#{pr.get('cycle')} "
            f"| `{pr.get('mac') or '-'}` | **{pr.get('outcome')}** "
            f"| {s.get('incoming_deauths', 0)} | {s.get('assoc_attempts', 0)} "
            f"| {', '.join(s.get('gateway_macs', [])) or '-'} "
            f"| {pr.get('rssi_min') if pr.get('rssi_min') is not None else '-'} "
            f"| {', '.join(pr.get('bands', [])) or '-'} |")
    lines.append("")
    v = session.get("verdict", {})
    lines.append(f"## Verdict: {v.get('verdict', 'unknown')}"
                 f" (confidence: {v.get('confidence', '-')})")
    lines.append("")
    lines.append(str(v.get("explanation", "")))
    lines.append("")
    if v.get("next_steps"):
        lines.append("Next steps:")
        for s in v["next_steps"]:
            lines.append(f"- {s}")
        lines.append("")
    timeline = session.get("timeline", [])
    if timeline:
        lines.append("## Evidence timeline (last 60 records)")
        lines.append("```")
        from netfend.services.link_watcher import format_record
        for rec in timeline[-60:]:
            lines.append(format_record(rec))
        lines.append("```")
    lines.append("")
    lines.append("Evidence log: link-evidence.jsonl — query any window with "
                 "`sudo netfend wifi events --kind deauth`.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# IdentityController — NM profile identity with a restore contract
# ---------------------------------------------------------------------------

class IdentityController:
    """Read / backup / apply / restore NM connection-profile identity.

    All nmcli interaction goes through injectable `run` (tests inject a
    fake). Property support varies across NM versions (e.g.
    ipv6.dhcp-send-hostname needs NM >= 1.36): a modify that fails on an
    unknown property drops the property from the supported set instead
    of failing the phase — the experiment degrades, it never aborts
    mid-flight (ADR-005 discipline).
    """

    BACKUP_NAME = "identity-backup.json"

    def __init__(self, profile: str, run=None, data_dir: Path = None):
        self.profile = profile
        self._run = run or _run
        self.data_dir = Path(data_dir) if data_dir else config_mod.DATA_DIR
        self.backup_file = self.data_dir / self.BACKUP_NAME
        self._unsupported_props: set = set()

    # -- reads -------------------------------------------------------------

    def read_props(self, props: List[str]) -> Dict[str, str]:
        """`nmcli -g p1,p2 connection show PROFILE` — one value per line.
        Empty values are normalized to the documented NM default
        (restoring '' is invalid nmcli input)."""
        supported = [p for p in props if p not in self._unsupported_props]
        if not supported:
            return {}
        out = self._run(["nmcli", "-g", ",".join(supported),
                         "connection", "show", self.profile])
        if out is None:
            return {}
        values = [v.strip() for v in out.splitlines()]
        result: Dict[str, str] = {}
        for i, prop in enumerate(supported):
            raw = values[i] if i < len(values) else ""
            result[prop] = raw if raw else _NM_DEFAULTS.get(prop, "")
        return result

    def current_mac(self, iface: str) -> Optional[str]:
        if not iface:
            return None
        out = self._run(["ip", "link", "show", iface])
        return parse_ip_link_mac(out) if out else None

    def pending_backup(self) -> Optional[Dict[str, Any]]:
        if not self.backup_file.exists():
            return None
        try:
            return json.loads(self.backup_file.read_text())
        except (OSError, json.JSONDecodeError):
            return {"unreadable": True}

    # -- backup / apply / restore -------------------------------------------

    def identity_props(self) -> Dict[str, str]:
        return self.read_props([MAC_PROP, BAND_PROP] + list(ANON_PROPS))

    def backup(self) -> Optional[Dict[str, Any]]:
        """Snapshot current identity props to disk (atomic write).

        Auto-heal: a leftover backup from an interrupted experiment is
        RESTORED first, never overwritten — the file is the recovery
        point; overwriting it would strand the original identity."""
        if self.backup_file.exists():
            self.restore()
        props = self.identity_props()
        if not props:
            return None
        snapshot = {"profile": self.profile, "created": time.time(),
                    "props": props}
        try:
            self.backup_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.backup_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(snapshot, indent=2))
            tmp.replace(self.backup_file)   # atomic
        except OSError:
            return None
        return snapshot

    def apply(self, props: Dict[str, str]) -> Dict[str, str]:
        """Apply identity props to the profile. Returns the props that
        actually applied (unsupported ones are skipped with a warning)."""
        applied: Dict[str, str] = {}
        for prop, value in props.items():
            if prop in self._unsupported_props:
                continue
            ok = self._run(["nmcli", "connection", "modify",
                            self.profile, prop, value]) is not None
            if ok:
                applied[prop] = value
            else:
                self._unsupported_props.add(prop)
                log_warn(f"nmcli rejected property {prop} "
                         f"(unsupported on this NetworkManager?) — skipped")
        return applied

    def apply_backup_props(self) -> Dict[str, str]:
        """Re-apply the backed-up identity WITHOUT deleting the backup
        (the 'real' phases of the experiment)."""
        snap = self.pending_backup()
        if not snap or not snap.get("props"):
            return {}
        return self.apply(snap["props"])

    def restore(self) -> bool:
        """Re-apply the backup and remove it only after a VERIFIED
        restore (re-read must match). Returns True when the profile is
        back to (or already at) its original state."""
        if not self.backup_file.exists():
            return True          # nothing to restore = already clean
        try:
            snapshot = json.loads(self.backup_file.read_text())
        except (OSError, json.JSONDecodeError):
            return False         # keep the file; manual recovery possible
        props = snapshot.get("props", {})
        applied = self.apply(props)
        now_vals = self.read_props(list(props))
        verified = all(now_vals.get(p) == props[p] for p in applied)
        if verified:
            try:
                self.backup_file.unlink()
            except OSError:
                pass
            log_info("identity restored and verified "
                     f"({len(applied)} properties)")
        else:
            log_warn("identity restore could not be VERIFIED — the backup "
                     "file was KEPT; retry with: netfend wifi identity "
                     "restore")
        return verified

    def reconnect(self, iface: Optional[str], timeout: int = 90) -> bool:
        """Disconnect + bring the profile up again (identity changes
        only take effect on re-activation)."""
        if iface:
            self._run(["nmcli", "device", "disconnect", iface], timeout=15)
        out = self._run(["nmcli", "connection", "up", self.profile],
                        timeout=timeout + 10)
        return out is not None


# ---------------------------------------------------------------------------
# DefaultProbe — live state probe (all reads, no state change)
# ---------------------------------------------------------------------------

class DefaultProbe:
    """Callable returning one state snapshot for the runner. Injectable
    `run` and `iface_getter` for tests."""

    def __init__(self, iface_getter: Callable[[], Optional[str]], run=None):
        self._iface_getter = iface_getter
        self._run = run or _run

    def __call__(self) -> Dict[str, Any]:
        iface = self._iface_getter() or ""
        rec: Dict[str, Any] = {
            "t": time.time(), "iface": iface, "nm_state": None,
            "associated": False, "ssid": None, "bssid": None,
            "ip": None, "gw_ip": None, "gw_ok": False,
            "rssi": None, "band": None,
        }
        out = self._run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"])
        if out:
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 3 and parts[0] == iface:
                    rec["nm_state"] = parts[2]
        if iface:
            iw_out = self._run(["iw", "dev", iface, "link"])
            if iw_out is not None:
                link = parse_iw_link_ext(iw_out)
                rec["associated"] = bool(link.get("connected"))
                rec["ssid"] = link.get("ssid")
                rec["bssid"] = link.get("bssid")
                rec["rssi"] = link.get("rssi")
                rec["band"] = band_from_freq(link.get("freq"))
            ip_out = self._run(["ip", "-4", "addr", "show", iface])
            if ip_out:
                m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", ip_out)
                if m:
                    rec["ip"] = m.group(1)
        if rec["ip"]:
            route = self._run(["ip", "route"])
            if route:
                gw = parse_default_route(route)
                if gw and gw.get("interface") == iface:
                    rec["gw_ip"] = gw.get("gateway")
        if rec["gw_ip"] and rec["associated"]:
            rec["gw_ok"] = self._run(
                ["ping", "-c", "1", "-W", "1", rec["gw_ip"]]) is not None
        return rec


# ---------------------------------------------------------------------------
# ABTestRunner
# ---------------------------------------------------------------------------

class ABTestRunner:
    """Orchestrates the identity A/B experiment.

    Injectables for hermetic tests: run (nmcli/ip/iw), probe (state
    snapshots), reconnect_fn, now_fn, sleep_fn, path (evidence log).
    Production wiring uses the defaults. The restore contract is
    enforced by try/finally around EVERY phase, plus the on-disk
    backup auto-heal — a crash mid-experiment cannot strand the
    original identity.
    """

    def __init__(self, profile: str = None, ssid: str = None,
                 cycles: int = None, dwell_s: int = None,
                 connect_timeout_s: int = None, probe_s: int = None,
                 band: str = None, random_first: bool = False,
                 anonymize_hostname: bool = None, confirm: bool = True,
                 run=None, path: Path = None, data_dir: Path = None,
                 now_fn=None, sleep_fn=None, probe=None,
                 reconnect_fn=None, iface: str = None):
        self.profile_name = profile or cfg("wifi", "abtest_profile")
        self.ssid_pin = ssid or cfg("wifi", "abtest_ssid")
        self.cycles = int(cycles or cfg("wifi", "abtest_cycles", 2))
        self.dwell_s = int(dwell_s or cfg("wifi", "abtest_dwell_s", 300))
        self.connect_timeout_s = int(connect_timeout_s
                                     or cfg("wifi", "abtest_connect_timeout_s", 90))
        self.probe_s = int(probe_s or cfg("wifi", "abtest_probe_s", 5))
        self.band = band
        self.random_first = random_first
        self.anonymize_hostname = (
            anonymize_hostname if anonymize_hostname is not None
            else bool(cfg("wifi", "abtest_anonymize_hostname", True)))
        self.confirm = confirm
        self._run = run or _run
        self._path = path
        self._now = now_fn or time.time
        self._sleep = sleep_fn or time.sleep
        self._probe = probe
        self._reconnect_fn = reconnect_fn
        self._iface_override = iface
        self.ctrl: Optional[IdentityController] = None
        self.iface: Optional[str] = None
        self.session: Dict[str, Any] = {}

    # -- helpers -------------------------------------------------------------

    def _evidence_path(self) -> Path:
        from netfend.services import link_watcher as lw
        return lw._evidence_path(self._path)

    def _marker(self, phase: str, cycle: int, detail: str, **extra):
        append_marker(self._evidence_path(), {
            "kind": "marker", "source": "abtest",
            "phase": f"{phase}#{cycle}", "detail": detail, **extra})

    def detect_profile(self) -> Tuple[Optional[str], str]:
        out = self._run(["nmcli", "-t", "-f",
                         "NAME,TYPE,DEVICE,ACTIVE", "connection", "show"])
        if out is None:
            return None, "nmcli-unavailable"
        conns = parse_nmcli_connections(out)
        return select_profile(conns, self.profile_name, self.ssid_pin)

    def detect_iface(self) -> Optional[str]:
        if self._iface_override:
            return self._iface_override
        out = self._run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"])
        if out:
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 3 and parts[1] == "wifi":
                    return parts[0]
        return None

    def _default_probe(self) -> DefaultProbe:
        return DefaultProbe(self.detect_iface, run=self._run)

    # -- identity per phase ---------------------------------------------------

    def _real_identity(self) -> Dict[str, str]:
        """Original props from the backup (or current read when no
        backup exists yet)."""
        snap = self.ctrl.pending_backup()
        props = dict(snap.get("props", {})) if snap else self.ctrl.identity_props()
        if self.band:
            props[BAND_PROP] = self.band
        return props

    def _random_identity(self) -> Dict[str, str]:
        props: Dict[str, str] = {MAC_PROP: random_local_mac()}
        if self.anonymize_hostname:
            for prop in ANON_PROPS:
                if not self.ctrl or prop not in self.ctrl._unsupported_props:
                    props[prop] = "no"
        if self.band:
            props[BAND_PROP] = self.band
        return props

    # -- experiment -------------------------------------------------------------

    def run(self) -> int:
        if cfg("general", "dry_run"):
            return self._print_plan_only()

        # profile + interface resolution
        profile, how = self.detect_profile()
        if profile is None:
            print("[netfend] could not pick a Wi-Fi connection profile "
                  f"({how}).")
            print("       Pin it explicitly:")
            print('         sudo netfend wifi abtest --profile "Home Wi-Fi"')
            print("       or by SSID:  sudo netfend wifi abtest --ssid FAYER")
            return 1
        self.iface = self.detect_iface()
        self.ctrl = IdentityController(profile, run=self._run)
        self._probe = self._probe or self._default_probe()
        self._reconnect_fn = self._reconnect_fn or (
            lambda: self.ctrl.reconnect(self.iface, self.connect_timeout_s))

        if self.confirm and not self._ask_confirmation(profile, how):
            print("[netfend] aborted — nothing was changed.")
            return 1

        session = self.session = {
            "started": self._now(), "finished": None,
            "profile": profile, "profile_selected_by": how,
            "iface": self.iface, "cycles": self.cycles,
            "dwell_s": self.dwell_s, "connect_timeout_s": self.connect_timeout_s,
            "band": self.band, "phase_results": [],
        }
        self._marker("session", 0, "A/B experiment session started",
                     profile=profile, iface=self.iface, cycles=self.cycles,
                     dwell_s=self.dwell_s)

        backup = self.ctrl.backup()
        if backup is None:
            print("[netfend] could not read the profile's identity "
                  "properties (nmcli) — aborting before touching anything.")
            return 1
        print(f"[netfend] identity backed up -> {self.ctrl.backup_file}")
        for prop, value in backup["props"].items():
            print(f"         {prop} = {value}")

        order = ["random", "real"] if self.random_first else ["real", "random"]
        try:
            index = 0
            for cycle in range(1, self.cycles + 1):
                for kind in order:
                    index += 1
                    session["phase_results"].append(
                        self._run_phase(kind, cycle, index))
            session["verdict"] = classify_verdict(session["phase_results"])
        except KeyboardInterrupt:
            print("\n[netfend] interrupted — restoring identity now...")
            session["verdict"] = {"verdict": "interrupted",
                                  "confidence": "unverified",
                                  "explanation": "interrupted by operator",
                                  "next_steps": []}
        finally:
            restored = self._restore_and_reconnect()
            session["restored"] = restored

        session["finished"] = self._now()
        session["timeline"] = evidence_query(
            self._evidence_path(), since=session["started"] - 1)
        self._write_report(session)
        self._print_summary(session)
        verdict_name = session.get("verdict", {}).get("verdict")
        return 1 if verdict_name == "interrupted" else 0

    # -- phases -------------------------------------------------------------------

    def _run_phase(self, kind: str, cycle: int, index: int) -> Dict[str, Any]:
        identity = (self._random_identity() if kind == "random"
                    else self._real_identity())
        applied = self.ctrl.apply(identity)
        mac = identity.get(MAC_PROP)
        start = self._now()
        self._marker(kind, cycle,
                     f"phase start: identity applied", mac=mac,
                     applied=applied)
        print(f"\n[netfend] phase {kind}#{cycle}: mac={mac} "
              f"(dwell {self.dwell_s}s)")

        reconnect_ok = self._reconnect_fn()
        polls: List[Dict[str, Any]] = []
        # -- wait for association + IP (bounded)
        deadline = self._now() + self.connect_timeout_s
        while self._now() < deadline:
            try:
                p = self._probe()
            except ProbeExhausted:
                break
            polls.append(p)
            if p.get("associated") and p.get("ip"):
                break
            self._sleep(self.probe_s)
        # -- dwell: keep observing (bounded)
        dwell_end = self._now() + self.dwell_s
        while self._now() < dwell_end:
            try:
                p = self._probe()
            except ProbeExhausted:
                break
            polls.append(p)
            self._sleep(self.probe_s)

        end = self._now()
        records = evidence_query(self._evidence_path(),
                                 since=start - 1, until=end + 1)
        result = classify_phase(polls, records)
        result.update({
            "index": index, "phase": kind, "cycle": cycle, "mac": mac,
            "applied": applied, "reconnect_ok": reconnect_ok,
            "started": start, "ended": end,
            "rssi_min": result.get("rssi_min"),
            "bands": result.get("bands"),
        })
        self._marker(kind, cycle,
                     f"phase end: outcome={result['outcome']}", mac=mac,
                     outcome=result["outcome"])
        print(f"[netfend]   -> outcome: {result['outcome']} "
              f"(incoming deauths: "
              f"{result['summary'].get('incoming_deauths', 0)})")
        return result

    def _restore_and_reconnect(self) -> bool:
        if self.ctrl is None:
            return True
        try:
            ok = self.ctrl.restore()
        except Exception as e:
            log_warn(f"identity restore raised: {e}")
            ok = False
        try:
            self._reconnect_fn()
        except Exception as e:
            log_warn(f"reconnect after restore failed: {e}")
        if not ok:
            print("[netfend] WARNING: identity restore could not be verified.")
            print(f"         The backup is kept at {self.ctrl.backup_file}")
            print("         Manual recovery:")
            print(f"           nmcli connection modify \"{self.ctrl.profile}\" "
                  "wifi.cloned-mac-address preserve")
            print(f"           nmcli connection up \"{self.ctrl.profile}\"")
            print("         or retry: sudo netfend wifi identity restore")
        else:
            print("[netfend] identity restored to the original settings "
                  "and reconnected.")
        return ok

    # -- plan / confirm / report ------------------------------------------------------

    def _plan_description(self) -> List[str]:
        lines = [
            f"phases   : {self.cycles} x (real, random)"
            + ("  [random first]" if self.random_first else ""),
            f"dwell    : {self.dwell_s}s observation per phase",
            f"timeout  : {self.connect_timeout_s}s per connection attempt",
            f"estimate : ~"
            f"{self.cycles * 2 * (self.connect_timeout_s + self.dwell_s) // 60}"
            " minutes total",
        ]
        if self.band:
            lines.append(f"band     : pinned to {self.band} for BOTH phases "
                         "(controlled comparison)")
        if self.anonymize_hostname:
            lines.append("anon     : MAC randomized + hostname NOT sent in "
                         "DHCP (random phases only)")
        lines.append("restore  : automatic in ALL cases (Ctrl-C too); "
                     "backup kept until verified")
        return lines

    def _print_plan_only(self) -> int:
        print("[netfend] dry-run — the experiment would run with:")
        for line in self._plan_description():
            print(f"         {line}")
        print("         Run without --dry-run to execute.")
        return 0

    def _ask_confirmation(self, profile: str, how: str) -> bool:
        print("NetFend identity A/B experiment")
        print("-" * 60)
        print(f"profile  : {profile} (selected: {how})")
        for line in self._plan_description():
            print(f"{line}")
        print("-" * 60)
        print("Your Wi-Fi will disconnect/reconnect several times. The")
        print("router, the password, and other devices are NOT touched.")
        try:
            answer = input("Proceed? [yes/N] ").strip().lower()
        except EOFError:
            return False
        return answer in ("y", "yes")

    def _write_report(self, session: Dict[str, Any]) -> None:
        try:
            reports_dir = config_mod.DATA_DIR / "abtest"
            reports_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.fromtimestamp(
                session.get("started") or time.time()).strftime("%Y%m%d-%H%M%S")
            json_path = reports_dir / f"{stamp}-report.json"
            md_path = reports_dir / f"{stamp}-report.md"
            json_path.write_text(json.dumps(session, indent=2, default=str))
            md_path.write_text(render_report_md(session))
            session["report_md"] = str(md_path)
            print(f"\n[netfend] report saved: {md_path}")
        except OSError as e:
            log_warn(f"could not write report: {e}")

    def _print_summary(self, session: Dict[str, Any]) -> None:
        v = session.get("verdict", {})
        print()
        print("=" * 64)
        print(f"  VERDICT: {v.get('verdict', 'unknown')}"
              f"  (confidence: {v.get('confidence', '-')})")
        print("=" * 64)
        for line in str(v.get("explanation", "")).split("\n"):
            print(f"  {line}")
        if v.get("next_steps"):
            print()
            print("  Next steps:")
            for step in v["next_steps"]:
                print(f"   - {step}")
        print()


# ---------------------------------------------------------------------------
# Entry-point helpers (CLI)
# ---------------------------------------------------------------------------

def latest_report_path() -> Optional[Path]:
    reports_dir = config_mod.DATA_DIR / "abtest"
    if not reports_dir.is_dir():
        return None
    reports = sorted(reports_dir.glob("*-report.md"))
    return reports[-1] if reports else None


def run_abtest(**kwargs) -> int:
    """CLI entry: flock + run. Returns exit code."""
    from netfend.services.link_watcher import acquire_lock
    fd, conflict = acquire_lock("/run/netfend.abtest.lock")
    if conflict is not None:
        print(f"[netfend] another A/B experiment is already running"
              + (f" (pid {conflict})" if conflict.isdigit() else "") + ".")
        return 1
    runner = ABTestRunner(**kwargs)
    try:
        return runner.run()
    except KeyboardInterrupt:
        print("\n[netfend] aborted.")
        return 1


def cmd_identity(action: str, profile: str = None, ssid: str = None) -> int:
    """CLI entry: identity show / random / restore."""
    runner = ABTestRunner(profile=profile, ssid=ssid, confirm=False)
    profile_name, how = runner.detect_profile()
    if profile_name is None:
        print(f"[netfend] could not pick a Wi-Fi connection profile ({how}).")
        print('         Pin it: --profile "Home Wi-Fi"  (or --ssid FAYER)')
        return 1
    iface = runner.detect_iface()
    ctrl = IdentityController(profile_name)
    print(f"profile : {profile_name} ({how})   interface: {iface or 'none'}")

    if action == "show":
        props = ctrl.identity_props()
        for prop, value in props.items():
            print(f"  {prop:28s} = {value}")
        current = ctrl.current_mac(iface) if iface else None
        print(f"  {'MAC currently in use':28s} = {current or 'unknown'}")
        pending = ctrl.pending_backup()
        if pending and not pending.get("unreadable"):
            created = pending.get("created")
            created_str = (datetime.fromtimestamp(created).astimezone()
                           .strftime("%Y-%m-%d %H:%M:%S") if created else "?")
            print(f"  PENDING BACKUP from {created_str}:")
            for prop, value in pending.get("props", {}).items():
                print(f"    {prop:26s} = {value}")
            print("  -> restore it with: sudo netfend wifi identity restore")
        elif pending:
            print("  WARNING: backup file exists but is unreadable — "
                  "check identity-backup.json manually")
        else:
            print("  no pending experiment backup (identity is original)")
        return 0

    if action == "random":
        backup = ctrl.backup()
        if backup is None:
            print("[netfend] could not back up the current identity — "
                  "nothing changed.")
            return 1
        mac = random_local_mac()
        ctrl.apply({MAC_PROP: mac})
        print(f"[netfend] randomized MAC applied to the profile: {mac}")
        print("         It takes effect on the next connection...")
        ok = ctrl.reconnect(iface)
        print("[netfend] reconnected." if ok
              else "[netfend] reconnection did not complete — check: "
                   f"nmcli connection up \"{profile_name}\"")
        print("[netfend] restore the original identity with:")
        print("           sudo netfend wifi identity restore")
        return 0 if ok else 1

    if action == "restore":
        ok = ctrl.restore()
        if ok:
            ctrl.reconnect(iface)
            print("[netfend] original identity restored, verified, and "
                  "reconnected.")
            return 0
        print(f"[netfend] restore could not be verified — backup kept at "
              f"{ctrl.backup_file}; manual recovery:")
        print(f"         nmcli connection modify \"{profile_name}\" "
              "wifi.cloned-mac-address preserve")
        return 1
    return 1
