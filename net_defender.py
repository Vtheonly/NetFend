#!/usr/bin/env python3
import os
import sys
import argparse
from colorama import Fore, Style

# Ensure netfend package is discoverable
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from netfend.utils.config import BLACKLIST_FILE, LOG_FILE
from netfend.utils.logging import log_info, log_err, log_success
from netfend.services.network_manager import NetworkManager
from netfend.services.threat_intelligence import ThreatIntelligence
from netfend.services.device_registry import DeviceRegistry
from netfend.services.defense_engine import DefenseEngine

def cmd_show_devices(registry: DeviceRegistry):
    devices = registry.get_devices()
    if not devices:
        print("[NetFend] No registered devices in DB.")
        return
    print(f"\n{'─' * 110}")
    print(f"  {Fore.CYAN}REGISTERED NETWORK CLIENTS{Style.RESET_ALL}")
    print(f"{'─' * 110}")
    print(f"  {'MAC Address':18s} │ {'IP Address':15s} │ {'Status':12s} │ {'Hostname':20s} │ {'Last Seen'}")
    print(f"{'─' * 110}")
    for mac, info in sorted(devices.items()):
        auth_status = f"{Fore.GREEN}Authorized{Style.RESET_ALL}" if info.get("is_authorized", False) else f"{Fore.RED}Unauthorized{Style.RESET_ALL}"
        print(f"  {mac:18s} │ {info.get('last_ip', 'unknown'):15s} │ {auth_status:21s} │ {info.get('hostname', 'Unknown')[:20]:20s} │ {info.get('last_seen')}")
    print(f"{'─' * 110}\n")

def cmd_authorize_device(registry: DeviceRegistry, mac: str, authorize: bool):
    success = registry.authorize_device(mac, authorize)
    if success:
        status_str = "AUTHORIZED" if authorize else "DE-AUTHORIZED"
        log_success(f"Device {mac} has been successfully {status_str}.")
    else:
        log_err(f"Device {mac} was not found in database. Discover or register it first.")

def cmd_add_device(registry: DeviceRegistry, mac: str, ip: str, hostname: str, auth: bool):
    registry.register_device(mac=mac, ip=ip, hostname=hostname, is_authorized=auth)
    status_str = "Authorized" if auth else "Unauthorized"
    log_success(f"Manually added/updated device {mac} ({ip}) as {status_str}.")

def cmd_blacklist_show(intel: ThreatIntelligence):
    lines = intel.get_status_report()
    if not lines:
        print("[NetFend] Blacklist is empty. No threats recorded.")
        return
    print(f"\n{'─' * 90}")
    print(f"  {Fore.CYAN}DYNAMIC BLACKLIST{Style.RESET_ALL}")
    print(f"{'─' * 90}")
    for line in lines:
        print(line)
    print(f"{'─' * 90}\n")

def cmd_blacklist_clear(intel: ThreatIntelligence):
    if BLACKLIST_FILE.exists():
        BLACKLIST_FILE.unlink()
        log_success("Threat intelligence blacklist cleared.")
    else:
        log_info("No blacklist file found.")

def main():
    parser = argparse.ArgumentParser(
        description="NetFend Pro — Enterprise Modular Anti-ARP & Client Management System"
    )
    parser.add_argument("-i", "--interface", help="Network interface to monitor and protect")
    
    # Client Management Commands
    parser.add_argument("--list-devices", action="store_true", help="List all discovered local clients")
    parser.add_argument("--authorize", metavar="MAC", help="Authorize a client MAC address")
    parser.add_argument("--deauthorize", metavar="MAC", help="Block/deauthorize a client MAC address")
    parser.add_argument("--register-manual", nargs=4, metavar=("MAC", "IP", "HOSTNAME", "AUTH_BOOL"),
                        help="Manually inject a client device: MAC IP HOSTNAME True|False")

    # Blacklist Management Commands
    parser.add_argument("--blacklist", action="store_true", help="Show the current dynamic threat blacklist")
    parser.add_argument("--blacklist-clear", action="store_true", help="Clear the dynamic threat blacklist")

    args = parser.parse_args()

    # Initialize Services
    intel = ThreatIntelligence()
    registry = DeviceRegistry()

    if args.list_devices:
        cmd_show_devices(registry)
    elif args.authorize:
        cmd_authorize_device(registry, args.authorize, True)
    elif args.deauthorize:
        cmd_authorize_device(registry, args.deauthorize, False)
    elif args.register_manual:
        mac, ip, hostname, auth_str = args.register_manual
        auth = auth_str.lower() in ("true", "1", "yes")
        cmd_add_device(registry, mac, ip, hostname, auth)
    elif args.blacklist:
        cmd_blacklist_show(intel)
    elif args.blacklist_clear:
        cmd_blacklist_clear(intel)
    else:
        if os.geteuid() != 0:
            log_err("NetFend Pro defense engine must be executed as root!")
            sys.exit(1)

        try:
            nm = NetworkManager(interface=args.interface)
            engine = DefenseEngine(network_mgr=nm, intel=intel, registry=registry)
            engine.start()
        except KeyboardInterrupt:
            engine.stop()
            log_info("Shutdown triggered by user.")
        except Exception as e:
            log_err(f"Fatal execution error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
