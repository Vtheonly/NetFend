#!/usr/bin/env python3
"""
NetFend Pro — Advanced Anti-ARP Spoofing Defense Engine
=======================================================
Features:
  1. Real-time ARP packet sniffing via Scapy
  2. Static ARP locking + arptables filtering
  3. Active mitigation (high-speed counter-ARP blasts)
  4. Dynamic blacklist with behavioral fingerprinting
  5. Graduated threat levels & countermeasures
  6. Persistent blacklist storage (survives restarts)
  7. Device fingerprinting to detect MAC-changers
"""

import os
import sys
import json
import time
import math
import hashlib
import threading
import argparse
import subprocess
import signal
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

from scapy.all import (
    conf, send, sendp, srp, sniff,
    ARP, Ether, get_if_hwaddr, get_if_addr
)
from colorama import init, Fore, Style

init(autoreset=True)

# ──────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────
BLACKLIST_DIR  = Path("/var/lib/netfend")
BLACKLIST_FILE = BLACKLIST_DIR / "blacklist.json"
LOG_FILE       = BLACKLIST_DIR / "netfend.log"

# Threat levels (graduated)
THREAT_MONITOR  = "MONITOR"    # First sighting, just watching
THREAT_SUSPECT  = "SUSPECT"    # Repeated anomalies
THREAT_HOSTILE  = "HOSTILE"    # Confirmed active attacker
THREAT_CRITICAL = "CRITICAL"   # Persistent, aggressive attacker

THREAT_HIERARCHY = [THREAT_MONITOR, THREAT_SUSPECT, THREAT_HOSTILE, THREAT_CRITICAL]

# Thresholds for escalation
ESCALATION_RULES = {
    THREAT_MONITOR:  {"attacks_to_next": 3,   "window_secs": 120},
    THREAT_SUSPECT:  {"attacks_to_next": 5,   "window_secs": 300},
    THREAT_HOSTILE:  {"attacks_to_next": 15,  "window_secs": 600},
    THREAT_CRITICAL: {"attacks_to_next": 999, "window_secs": 999},  # max level
}

# Countermeasure intensity per threat level
COUNTERMEASURE_PROFILE = {
    THREAT_MONITOR:  {"blast_count": 3,   "blast_interval": 0.05, "loop_sleep": 1.0},
    THREAT_SUSPECT:  {"blast_count": 8,   "blast_interval": 0.02, "loop_sleep": 0.5},
    THREAT_HOSTILE:  {"blast_count": 15,  "blast_interval": 0.01, "loop_sleep": 0.2},
    THREAT_CRITICAL: {"blast_count": 30,  "blast_interval": 0.005, "loop_sleep": 0.05},
}


# ──────────────────────────────────────────────
# THREAT INTELLIGENCE ENGINE
# ──────────────────────────────────────────────
class ThreatProfile:
    """Tracks behavioral data for a single attacker identity."""

    def __init__(self, mac, first_seen=None):
        self.mac = mac
        self.threat_level = THREAT_MONITOR
        self.first_seen = first_seen or datetime.now().isoformat()
        self.last_seen = datetime.now().isoformat()
        self.attack_timestamps = []          # ISO timestamps of each attack event
        self.techniques = set()               # e.g. "gateway_spoof", "identity_spoof"
        self.spoofed_ips = set()              # IPs this MAC has tried to impersonate
        self.burst_intervals = []             # Time deltas between consecutive attacks (fingerprint)
        self.total_attacks = 0
        self.notes = []

    def record_attack(self, technique, spoofed_ip=None):
        now = datetime.now()
        self.last_seen = now.isoformat()
        self.total_attacks += 1
        self.techniques.add(technique)
        if spoofed_ip:
            self.spoofed_ips.add(spoofed_ip)

        # Record burst interval for fingerprinting
        if self.attack_timestamps:
            last = datetime.fromisoformat(self.attack_timestamps[-1])
            delta = (now - last).total_seconds()
            self.burst_intervals.append(round(delta, 4))
            # Keep only last 100 intervals
            self.burst_intervals = self.burst_intervals[-100:]

        self.attack_timestamps.append(now.isoformat())
        # Keep only last 500 timestamps
        self.attack_timestamps = self.attack_timestamps[-500:]

        self._evaluate_escalation()

    def _evaluate_escalation(self):
        """Check if we should escalate the threat level."""
        idx = THREAT_HIERARCHY.index(self.threat_level)
        if idx >= len(THREAT_HIERARCHY) - 1:
            return  # Already at max

        rule = ESCALATION_RULES[self.threat_level]
        window = rule["window_secs"]
        threshold = rule["attacks_to_next"]

        cutoff = datetime.now() - timedelta(seconds=window)
        recent = [t for t in self.attack_timestamps
                  if datetime.fromisoformat(t) > cutoff]

        if len(recent) >= threshold:
            self.threat_level = THREAT_HIERARCHY[idx + 1]
            return True
        return False

    def get_behavior_fingerprint(self):
        """
        Generate a behavioral fingerprint based on attack timing patterns.
        Even if the attacker changes their MAC, their tool's timing signature
        remains consistent. This allows us to correlate new MACs to known attackers.
        """
        if len(self.burst_intervals) < 5:
            return None

        intervals = self.burst_intervals[-50:]
        mean = sum(intervals) / len(intervals)
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        stddev = math.sqrt(variance) if variance > 0 else 0

        # Quantize to reduce noise
        q_mean = round(mean, 2)
        q_std = round(stddev, 2)
        techniques_str = ",".join(sorted(self.techniques))

        fingerprint_str = f"{q_mean}:{q_std}:{techniques_str}"
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

    def to_dict(self):
        return {
            "mac": self.mac,
            "threat_level": self.threat_level,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "total_attacks": self.total_attacks,
            "techniques": list(self.techniques),
            "spoofed_ips": list(self.spoofed_ips),
            "burst_intervals": self.burst_intervals[-50:],
            "attack_timestamps": self.attack_timestamps[-50:],
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d):
        p = cls(d["mac"], d.get("first_seen"))
        p.threat_level = d.get("threat_level", THREAT_MONITOR)
        p.last_seen = d.get("last_seen", p.first_seen)
        p.total_attacks = d.get("total_attacks", 0)
        p.techniques = set(d.get("techniques", []))
        p.spoofed_ips = set(d.get("spoofed_ips", []))
        p.burst_intervals = d.get("burst_intervals", [])
        p.attack_timestamps = d.get("attack_timestamps", [])
        p.notes = d.get("notes", [])
        return p


class ThreatIntelligence:
    """Manages the dynamic blacklist and behavioral fingerprinting database."""

    def __init__(self):
        self.profiles = {}          # MAC → ThreatProfile
        self.fingerprint_map = {}   # fingerprint_hash → set of MACs
        self._lock = threading.Lock()
        self._load()

    def _ensure_dir(self):
        BLACKLIST_DIR.mkdir(parents=True, exist_ok=True)

    def _load(self):
        self._ensure_dir()
        if BLACKLIST_FILE.exists():
            try:
                with open(BLACKLIST_FILE, "r") as f:
                    data = json.load(f)
                for entry in data.get("profiles", []):
                    p = ThreatProfile.from_dict(entry)
                    self.profiles[p.mac] = p
                self.fingerprint_map = {
                    k: set(v) for k, v in data.get("fingerprint_map", {}).items()
                }
                _print_info(f"Loaded {len(self.profiles)} threat profiles from blacklist.")
            except Exception as e:
                _print_warn(f"Could not load blacklist: {e}")

    def save(self):
        self._ensure_dir()
        with self._lock:
            data = {
                "profiles": [p.to_dict() for p in self.profiles.values()],
                "fingerprint_map": {k: list(v) for k, v in self.fingerprint_map.items()},
                "last_saved": datetime.now().isoformat(),
            }
            try:
                with open(BLACKLIST_FILE, "w") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                _print_warn(f"Could not save blacklist: {e}")

    def record_attack(self, mac, technique, spoofed_ip=None):
        with self._lock:
            if mac not in self.profiles:
                self.profiles[mac] = ThreatProfile(mac)
                _print_alert(f"New attacker added to blacklist: {mac}")

            profile = self.profiles[mac]
            old_level = profile.threat_level
            profile.record_attack(technique, spoofed_ip)

            if profile.threat_level != old_level:
                _print_escalation(mac, old_level, profile.threat_level)

            # Update fingerprint map
            fp = profile.get_behavior_fingerprint()
            if fp:
                if fp not in self.fingerprint_map:
                    self.fingerprint_map[fp] = set()
                self.fingerprint_map[fp].add(mac)

                # Check if this fingerprint matches OTHER known MACs
                aliases = self.fingerprint_map[fp] - {mac}
                if aliases:
                    alias_str = ", ".join(aliases)
                    msg = f"MAC {mac} matches behavioral fingerprint of: {alias_str}"
                    _print_warn(f"[FINGERPRINT MATCH] {msg}")
                    if msg not in profile.notes:
                        profile.notes.append(msg)
                    # Inherit the highest threat level from aliases
                    for alias_mac in aliases:
                        if alias_mac in self.profiles:
                            alias_lvl = self.profiles[alias_mac].threat_level
                            alias_idx = THREAT_HIERARCHY.index(alias_lvl)
                            cur_idx = THREAT_HIERARCHY.index(profile.threat_level)
                            if alias_idx > cur_idx:
                                profile.threat_level = alias_lvl
                                _print_escalation(mac, THREAT_HIERARCHY[cur_idx], alias_lvl,
                                                  reason="inherited from fingerprint match")

        # Auto-save periodically
        self.save()
        return self.profiles[mac]

    def get_threat_level(self, mac):
        with self._lock:
            if mac in self.profiles:
                return self.profiles[mac].threat_level
        return None

    def get_countermeasure_profile(self, mac):
        level = self.get_threat_level(mac)
        if level:
            return COUNTERMEASURE_PROFILE[level]
        return COUNTERMEASURE_PROFILE[THREAT_MONITOR]

    def get_status_report(self):
        with self._lock:
            lines = []
            for mac, p in sorted(self.profiles.items(), key=lambda x: x[1].total_attacks, reverse=True):
                lines.append(
                    f"  {mac}  │ {p.threat_level:8s} │ {p.total_attacks:4d} attacks │ "
                    f"techniques: {', '.join(p.techniques)} │ last: {p.last_seen}"
                )
            return lines


# ──────────────────────────────────────────────
# LOGGING / PRINTING HELPERS
# ──────────────────────────────────────────────
def _log(msg):
    try:
        BLACKLIST_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass

def _print_info(msg):
    text = f"[{Fore.CYAN}NetFend{Style.RESET_ALL}] {msg}"
    print(text)
    _log(msg)

def _print_warn(msg):
    text = f"[{Fore.YELLOW}WARNING{Style.RESET_ALL}] {msg}"
    print(text)
    _log(f"WARNING: {msg}")

def _print_err(msg):
    text = f"[{Fore.RED}ERROR{Style.RESET_ALL}] {msg}"
    print(text)
    _log(f"ERROR: {msg}")

def _print_success(msg):
    text = f"[{Fore.GREEN}OK{Style.RESET_ALL}] {msg}"
    print(text)
    _log(msg)

def _print_alert(msg):
    text = f"[{Fore.RED}{Style.BRIGHT}⚠ BLACKLIST{Style.RESET_ALL}] {msg}"
    print(text)
    _log(f"BLACKLIST: {msg}")

def _print_escalation(mac, old_level, new_level, reason="attack pattern escalation"):
    color = {
        THREAT_MONITOR: Fore.WHITE,
        THREAT_SUSPECT: Fore.YELLOW,
        THREAT_HOSTILE: Fore.RED,
        THREAT_CRITICAL: f"{Fore.RED}{Style.BRIGHT}",
    }
    new_c = color.get(new_level, Fore.WHITE)
    msg = f"[ESCALATION] {mac}: {old_level} → {new_c}{new_level}{Style.RESET_ALL} ({reason})"
    print(f"[{Fore.MAGENTA}THREAT{Style.RESET_ALL}] {msg}")
    _log(f"ESCALATION: {mac}: {old_level} → {new_level} ({reason})")


# ──────────────────────────────────────────────
# CORE DEFENSE ENGINE
# ──────────────────────────────────────────────
class NetFendPro:
    def __init__(self, interface=None):
        self.interface = interface or self._detect_interface()
        self.my_ip = get_if_addr(self.interface)
        self.my_mac = get_if_hwaddr(self.interface)
        self.gw_ip = self._detect_gateway()
        self.gw_mac = self._resolve_mac(self.gw_ip)

        self.running = False
        self.mitigation_thread = None
        self.status_thread = None
        self.intel = ThreatIntelligence()

        # Track current highest active threat for mitigation intensity
        self._active_threat_level = THREAT_MONITOR
        self._active_threat_lock = threading.Lock()

        if not all([self.my_ip, self.my_mac, self.gw_ip, self.gw_mac]):
            _print_err("Could not detect all network parameters. Aborting.")
            sys.exit(1)

        conf.iface = self.interface
        conf.verb = 0

    # ── Network Detection ──

    def _detect_interface(self):
        try:
            out = subprocess.check_output("ip route", shell=True).decode()
            for line in out.split('\n'):
                if 'default' in line:
                    return line.split('dev')[1].split()[0]
        except Exception:
            pass
        return conf.iface

    def _detect_gateway(self):
        try:
            out = subprocess.check_output("ip route", shell=True).decode()
            for line in out.split('\n'):
                if 'default' in line:
                    return line.split('via')[1].split()[0]
        except Exception:
            pass
        return conf.route.route("0.0.0.0")[2]

    def _resolve_mac(self, ip):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                      timeout=2, retry=3, verbose=False)
        for _, rcv in ans:
            return rcv[Ether].src
        return None

    # ── Hardening ──

    def _lock_arp(self):
        _print_info("Locking local ARP table...")
        subprocess.call(
            f"ip neigh replace {self.gw_ip} lladdr {self.gw_mac} dev {self.interface} nud permanent",
            shell=True, stderr=subprocess.DEVNULL
        )

    def _apply_arptables(self):
        _print_info("Applying strict packet filters using arptables...")
        subprocess.call(["arptables", "-F"], stderr=subprocess.DEVNULL)
        # Block ARP from gateway IP but wrong MAC
        subprocess.call(
            f"arptables -A INPUT -s {self.gw_ip} --src-mac ! {self.gw_mac} -j DROP",
            shell=True, stderr=subprocess.DEVNULL
        )
        # Block ARP spoofing our own IP
        subprocess.call(
            f"arptables -A INPUT -s {self.my_ip} -j DROP",
            shell=True, stderr=subprocess.DEVNULL
        )

    def _clear_arptables(self):
        subprocess.call(["arptables", "-F"], stderr=subprocess.DEVNULL)

    def _restore_arp(self):
        _print_info("Restoring ARP cache to normal state...")
        send(ARP(op=2, pdst=self.gw_ip, psrc=self.my_ip,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.my_mac), count=5, verbose=False)
        send(ARP(op=2, pdst=self.my_ip, psrc=self.gw_ip,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gw_mac), count=5, verbose=False)

    # ── Active Mitigation (Adaptive) ──

    def _active_mitigation(self):
        _print_info("Active mitigation thread initialized. Sending legitimate ARP replies to maintain integrity...")
        pkt_to_gw = (Ether(dst=self.gw_mac, src=self.my_mac) /
                     ARP(op=2, psrc=self.my_ip, hwsrc=self.my_mac,
                         pdst=self.gw_ip, hwdst=self.gw_mac))

        while self.running:
            try:
                with self._active_threat_lock:
                    level = self._active_threat_level
                profile = COUNTERMEASURE_PROFILE[level]

                sendp(pkt_to_gw, count=profile["blast_count"],
                      inter=profile["blast_interval"], verbose=False)
                time.sleep(profile["loop_sleep"])
            except Exception as e:
                _print_err(f"Mitigation loop error: {e}")
                time.sleep(1)

    def _update_active_threat(self, level):
        with self._active_threat_lock:
            cur_idx = THREAT_HIERARCHY.index(self._active_threat_level)
            new_idx = THREAT_HIERARCHY.index(level)
            if new_idx > cur_idx:
                self._active_threat_level = level

    # ── Threat Detection ──

    def _sniff_callback(self, packet):
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]

        # ── CASE 1: Someone spoofing the gateway ──
        if arp.psrc == self.gw_ip and arp.hwsrc != self.gw_mac:
            attacker_mac = arp.hwsrc
            profile = self.intel.record_attack(
                attacker_mac, "gateway_spoof", spoofed_ip=self.gw_ip
            )

            level = profile.threat_level
            level_color = {
                THREAT_MONITOR: Fore.WHITE, THREAT_SUSPECT: Fore.YELLOW,
                THREAT_HOSTILE: Fore.RED, THREAT_CRITICAL: f"{Fore.RED}{Style.BRIGHT}",
            }.get(level, Fore.WHITE)

            _print_warn(
                f"[{Fore.RED}ATTACK DETECTED{Style.RESET_ALL}] "
                f"Device {attacker_mac} is attempting gateway spoofing. "
                f"Threat: {level_color}{level}{Style.RESET_ALL} "
                f"(total: {profile.total_attacks})"
            )

            self._update_active_threat(level)

        # ── CASE 2: Someone spoofing OUR identity ──
        elif arp.psrc == self.my_ip and arp.hwsrc != self.my_mac:
            attacker_mac = arp.hwsrc
            profile = self.intel.record_attack(
                attacker_mac, "identity_spoof", spoofed_ip=self.my_ip
            )

            level = profile.threat_level
            _print_warn(
                f"[{Fore.RED}ATTACK DETECTED{Style.RESET_ALL}] "
                f"Device {attacker_mac} is impersonating OUR IP ({self.my_ip}). "
                f"Threat: {level} (total: {profile.total_attacks})"
            )
            self._update_active_threat(level)

        # ── CASE 3: Gratuitous ARP flood (potential reconnaissance) ──
        elif arp.op == 2 and arp.pdst == arp.psrc:
            sender_mac = arp.hwsrc
            # Only flag if it's not from us or the gateway
            if sender_mac not in (self.my_mac, self.gw_mac):
                # Soft tracking – could be benign, but worth monitoring
                if sender_mac in self.intel.profiles:
                    profile = self.intel.record_attack(
                        sender_mac, "gratuitous_flood", spoofed_ip=arp.psrc
                    )

    # ── Status Report ──

    def _status_reporter(self):
        """Periodically prints a summary of the blacklist."""
        while self.running:
            time.sleep(60)  # Report every 60 seconds
            if not self.running:
                break
            lines = self.intel.get_status_report()
            if lines:
                print(f"\n{'─' * 90}")
                print(f"  {Fore.CYAN}{Style.BRIGHT}DYNAMIC BLACKLIST STATUS{Style.RESET_ALL}  "
                      f"({datetime.now().strftime('%H:%M:%S')})")
                print(f"{'─' * 90}")
                for line in lines:
                    print(line)
                print(f"{'─' * 90}\n")

    # ── Main Loop ──

    def start(self):
        banner = f"""
{Fore.GREEN}{Style.BRIGHT}╔══════════════════════════════════════════════╗
║         NetFend Pro — Defense Engine         ║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
  Interface  : {self.interface}
  Your IP    : {self.my_ip}
  Your MAC   : {self.my_mac}
  Gateway IP : {self.gw_ip}
  Gateway MAC: {self.gw_mac}
"""
        print(banner)

        self.running = True

        # 1. Lock outbound
        self._lock_arp()

        # 2. Filter inbound
        self._apply_arptables()

        # 3. Start adaptive mitigation
        self.mitigation_thread = threading.Thread(target=self._active_mitigation, daemon=True)
        self.mitigation_thread.start()

        # 4. Start status reporter
        self.status_thread = threading.Thread(target=self._status_reporter, daemon=True)
        self.status_thread.start()

        # 5. Sniff for attacks
        _print_info("Starting real-time threat detection engine...")
        _print_info("Press Ctrl+C to stop and restore network.\n")

        def _signal_handler(sig, frame):
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        try:
            sniff(filter="arp", prn=self._sniff_callback, store=0, iface=self.interface)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        print()
        _print_info("Shutting down NetFend Pro...")
        self.running = False

        if self.mitigation_thread:
            self.mitigation_thread.join(timeout=2)

        # Save final state
        self.intel.save()

        self._clear_arptables()
        self._restore_arp()

        _print_info("Unlocking ARP table...")
        subprocess.call(
            f"ip neigh replace {self.gw_ip} dev {self.interface} nud reachable",
            shell=True, stderr=subprocess.DEVNULL
        )

        # Final report
        lines = self.intel.get_status_report()
        if lines:
            print(f"\n{'─' * 90}")
            print(f"  {Fore.CYAN}{Style.BRIGHT}FINAL BLACKLIST REPORT{Style.RESET_ALL}")
            print(f"{'─' * 90}")
            for line in lines:
                print(line)
            print(f"{'─' * 90}")
            print(f"  Blacklist saved to: {BLACKLIST_FILE}")
            print(f"  Log saved to: {LOG_FILE}")
            print(f"{'─' * 90}\n")

        _print_success("Defense deactivated. Network restored to normal state.")


# ──────────────────────────────────────────────
# CLI: BLACKLIST MANAGEMENT
# ──────────────────────────────────────────────
def cmd_blacklist_show():
    """Show the current blacklist."""
    intel = ThreatIntelligence()
    lines = intel.get_status_report()
    if not lines:
        print("[NetFend] Blacklist is empty. No threats recorded.")
        return
    print(f"\n{'─' * 90}")
    print(f"  {Fore.CYAN}{Style.BRIGHT}DYNAMIC BLACKLIST{Style.RESET_ALL}")
    print(f"{'─' * 90}")
    for line in lines:
        print(line)
    print(f"{'─' * 90}\n")


def cmd_blacklist_clear():
    """Clear the entire blacklist."""
    if BLACKLIST_FILE.exists():
        BLACKLIST_FILE.unlink()
        print("[NetFend] Blacklist cleared.")
    else:
        print("[NetFend] No blacklist file found.")


def cmd_blacklist_detail(mac):
    """Show detailed info for a specific MAC."""
    intel = ThreatIntelligence()
    if mac not in intel.profiles:
        print(f"[NetFend] MAC {mac} not found in blacklist.")
        return

    p = intel.profiles[mac]
    fp = p.get_behavior_fingerprint() or "insufficient data"
    print(f"""
{'─' * 60}
  MAC:             {p.mac}
  Threat Level:    {p.threat_level}
  First Seen:      {p.first_seen}
  Last Seen:       {p.last_seen}
  Total Attacks:   {p.total_attacks}
  Techniques:      {', '.join(p.techniques)}
  Spoofed IPs:     {', '.join(p.spoofed_ips)}
  Fingerprint:     {fp}
  Notes:           {'; '.join(p.notes) if p.notes else 'none'}
{'─' * 60}
""")


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NetFend Pro — Advanced Anti-ARP Spoofing Defense",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  (default)              Start the defense engine
  --blacklist            Show the dynamic blacklist
  --blacklist-clear      Clear the blacklist
  --blacklist-detail MAC Show details for a specific MAC address
        """
    )
    parser.add_argument("-i", "--interface", help="Network interface to protect")
    parser.add_argument("--blacklist", action="store_true", help="Show the dynamic blacklist")
    parser.add_argument("--blacklist-clear", action="store_true", help="Clear the blacklist")
    parser.add_argument("--blacklist-detail", metavar="MAC", help="Show detail for a MAC")

    args = parser.parse_args()

    if args.blacklist:
        cmd_blacklist_show()
    elif args.blacklist_clear:
        cmd_blacklist_clear()
    elif args.blacklist_detail:
        cmd_blacklist_detail(args.blacklist_detail)
    else:
        if os.geteuid() != 0:
            print(f"{Fore.RED}ERROR: NetFend Pro must be run as root!{Style.RESET_ALL}")
            sys.exit(1)

        defender = NetFendPro(interface=args.interface)
        defender.start()
