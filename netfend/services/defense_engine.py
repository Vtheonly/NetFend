import time
import threading
from typing import Optional, Dict, Any
from scapy.all import Ether, ARP, sendp, sniff
from netfend.utils.config import THREAT_MONITOR, THREAT_HIERARCHY, COUNTERMEASURE_PROFILE
from netfend.utils.logging import log_info, log_warn, log_err, log_success
from netfend.services.network_manager import NetworkManager
from netfend.services.threat_intelligence import ThreatIntelligence
from netfend.services.device_registry import DeviceRegistry

class DefenseEngine:
    """Core defender orchestrating network monitoring, packet analysis, active ARP blast mitigation, and blocking unauthorized hosts."""

    def __init__(self, network_mgr: NetworkManager, intel: ThreatIntelligence, registry: DeviceRegistry):
        self.nm = network_mgr
        self.intel = intel
        self.registry = registry

        self.my_ip = self.nm.get_my_ip()
        self.my_mac = self.nm.get_my_mac()
        self.gw_ip = self.nm.detect_gateway_ip()
        self.gw_mac = self.nm.resolve_mac(self.gw_ip)

        self.running = False
        self.mitigation_thread: Optional[threading.Thread] = None
        self.status_thread: Optional[threading.Thread] = None
        self.discovery_thread: Optional[threading.Thread] = None

        self._active_threat_level = THREAT_MONITOR
        self._active_threat_lock = threading.Lock()

        if not all([self.my_ip, self.my_mac, self.gw_ip, self.gw_mac]):
            log_err("Could not initialize all network variables. Ensure connectivity.")
            raise RuntimeError("Missing networking parameters")

    def _update_active_threat(self, level: str):
        with self._active_threat_lock:
            try:
                cur_idx = THREAT_HIERARCHY.index(self._active_threat_level)
                new_idx = THREAT_HIERARCHY.index(level)
                if new_idx > cur_idx:
                    self._active_threat_level = level
            except ValueError:
                pass

    def _active_mitigation_loop(self):
        """Active mitigation loop that counters spoofers by sending legitimate gateway mappings."""
        log_info("Active mitigation thread initialized. Monitoring gateway spoofing...")
        
        # Craft safe template frames pointing to accurate gateway mapping
        pkt_to_gw = (Ether(dst=self.gw_mac, src=self.my_mac) /
                     ARP(op=2, psrc=self.my_ip, hwsrc=self.my_mac,
                         pdst=self.gw_ip, hwdst=self.gw_mac))

        while self.running:
            try:
                with self._active_threat_lock:
                    level = self._active_threat_level
                profile = COUNTERMEASURE_PROFILE.get(level, COUNTERMEASURE_PROFILE[THREAT_MONITOR])

                # Send corrective packets to gateway to keep our connection open
                sendp(pkt_to_gw, count=profile["blast_count"],
                      inter=profile["blast_interval"], verbose=False)
                
                # Active Wi-Fi access management: Disconnect unauthorized devices
                self._mitigate_unauthorized_devices()
                
                time.sleep(profile["loop_sleep"])
            except Exception as e:
                log_err(f"Mitigation loop error: {e}")
                time.sleep(1)

    def _mitigate_unauthorized_devices(self):
        """
        Actively disconnects unauthorized devices from accessing the network.
        It target-blasts them with ARP spoofing redirects (mapping gateway IP to a dead MAC)
        and sends gateway redirects mapping their IP to a dead MAC, effectively isolating them.
        """
        registered = self.registry.get_devices()
        unauthorized_macs = [mac for mac, info in registered.items() if not info.get("is_authorized", False)]
        
        dead_mac = "00:00:00:00:00:00"
        
        for u_mac in unauthorized_macs:
            info = registered[u_mac]
            target_ip = info.get("last_ip")
            if not target_ip:
                continue
            
            # Send spoofed ARP reply to the target telling them the Gateway's MAC is a dead MAC
            # This cuts off their outbound network path.
            poison_target = (Ether(dst=u_mac, src=self.my_mac) /
                             ARP(op=2, psrc=self.gw_ip, hwsrc=dead_mac, pdst=target_ip, hwdst=u_mac))
            
            # Send spoofed ARP reply to the gateway telling them the target's MAC is dead
            # This cuts off their inbound path.
            poison_gateway = (Ether(dst=self.gw_mac, src=self.my_mac) /
                              ARP(op=2, psrc=target_ip, hwsrc=dead_mac, pdst=self.gw_ip, hwdst=self.gw_mac))
            
            try:
                sendp(poison_target, count=2, verbose=False)
                sendp(poison_gateway, count=2, verbose=False)
            except Exception:
                pass

    def _periodic_discovery_loop(self):
        """Discovers new/active local IP/MAC devices to update registry and flag unauthorized ones."""
        while self.running:
            try:
                hosts = self.nm.scan_local_network()
                for ip, mac in hosts:
                    if mac == self.my_mac or mac == self.gw_mac:
                        continue
                    # Check if registered. If not, log it.
                    is_registered = mac in self.registry.devices
                    # Register (by default first seen is not authorized)
                    self.registry.register_device(mac=mac, ip=ip, hostname="Discovered Host")
                    if not is_registered:
                        log_warn(f"Discovered new unregistered Wi-Fi client device: {mac} at {ip}")
            except Exception as e:
                log_err(f"Discovery thread error: {e}")
            
            # Scan every 30 seconds
            for _ in range(30):
                if not self.running:
                    break
                time.sleep(1)

    def _sniff_callback(self, packet):
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]

        # Register/update the sender device in the registry to track who is currently active
        sender_mac = arp.hwsrc.lower()
        sender_ip = arp.psrc
        if sender_mac != "00:00:00:00:00:00" and sender_mac != "ff:ff:ff:ff:ff:ff":
            self.registry.register_device(mac=sender_mac, ip=sender_ip)

        # ── Threat Checking: Check if device is spoofing or trying to impersonate ──
        # CASE 1: Device pretending to be the Gateway
        if arp.psrc == self.gw_ip and arp.hwsrc.lower() != self.gw_mac.lower():
            attacker_mac = arp.hwsrc
            profile = self.intel.record_attack(attacker_mac, "gateway_spoof", spoofed_ip=self.gw_ip)
            log_warn(f"[ATTACK DETECTED] Host {attacker_mac} is spoofing the gateway IP {self.gw_ip}! Level: {profile.threat_level}")
            self._update_active_threat(profile.threat_level)

        # CASE 2: Device spoofing OUR IP Address
        elif arp.psrc == self.my_ip and arp.hwsrc.lower() != self.my_mac.lower():
            attacker_mac = arp.hwsrc
            profile = self.intel.record_attack(attacker_mac, "identity_spoof", spoofed_ip=self.my_ip)
            log_warn(f"[ATTACK DETECTED] Host {attacker_mac} is spoofing OUR local IP {self.my_ip}! Level: {profile.threat_level}")
            self._update_active_threat(profile.threat_level)

        # CASE 3: Floods / anomaly checks
        elif arp.op == 2 and arp.pdst == arp.psrc:
            # Gratuitous ARP from arbitrary MACs
            if sender_mac not in (self.my_mac.lower(), self.gw_mac.lower()):
                if sender_mac in self.intel.profiles:
                    profile = self.intel.record_attack(sender_mac, "gratuitous_flood", spoofed_ip=arp.psrc)
                    self._update_active_threat(profile.threat_level)

    def _status_reporter(self):
        while self.running:
            for _ in range(60):
                if not self.running:
                    break
                time.sleep(1)
            if not self.running:
                break
            
            lines = self.intel.get_status_report()
            if lines:
                print(f"\n{'─' * 90}")
                print(f"  DYNAMIC BLACKLIST STATUS ({time.strftime('%H:%M:%S')})")
                print(f"{'─' * 90}")
                for line in lines:
                    print(line)
                print(f"{'─' * 90}\n")

    def start(self):
        banner = f"""
  Network Interface: {self.nm.interface}
  Your IP Address:   {self.my_ip}
  Your MAC Address:  {self.my_mac}
  Gateway IP:        {self.gw_ip}
  Gateway MAC:       {self.gw_mac}
"""
        log_info(banner)
        self.running = True

        # Harden OS ARP Tables
        self.nm.lock_arp_entry(self.gw_ip, self.gw_mac)
        self.nm.apply_arptables_rules(self.my_ip, self.my_mac, self.gw_ip, self.gw_mac)

        # Start mitigation
        self.mitigation_thread = threading.Thread(target=self._active_mitigation_loop, daemon=True)
        self.mitigation_thread.start()

        # Start device discovery scanner
        self.discovery_thread = threading.Thread(target=self._periodic_discovery_loop, daemon=True)
        self.discovery_thread.start()

        # Start blacklist status reporter
        self.status_thread = threading.Thread(target=self._status_reporter, daemon=True)
        self.status_thread.start()

        log_info("Real-time threat monitoring and device isolation system is active.")
        log_info("Sniffing network traffic. Press Ctrl+C to terminate...")

        try:
            sniff(filter="arp", prn=self._sniff_callback, store=0, iface=self.nm.interface)
        except Exception as e:
            log_err(f"Sniffer execution error: {e}")
            self.stop()

    def stop(self):
        log_info("Stopping Active Defense system and restoring network routing...")
        self.running = False

        if self.mitigation_thread:
            self.mitigation_thread.join(timeout=2)
        if self.discovery_thread:
            self.discovery_thread.join(timeout=2)
        if self.status_thread:
            self.status_thread.join(timeout=2)

        self.intel.save()
        self.registry.save()

        # Clear kernel filters
        self.nm.clear_arptables_rules()
        self.nm.send_arp_restoration_blasts(self.my_ip, self.my_mac, self.gw_ip, self.gw_mac)
        self.nm.unlock_arp_entry(self.gw_ip)

        log_success("System deactivated successfully.")
