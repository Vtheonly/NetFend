import subprocess
import time
from typing import Optional, List, Tuple
from scapy.all import srp, send, sendp, Ether, ARP, conf
from netfend.utils.logging import log_info, log_warn, log_success, log_err

class NetworkManager:
    """Encapsulates system route inspection, ARP resolving, static entry injection, and traffic rules."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or self._detect_interface()
        conf.iface = self.interface
        conf.verb = 0

    def _detect_interface(self) -> str:
        try:
            out = subprocess.check_output("ip route", shell=True).decode()
            for line in out.split('\n'):
                if 'default' in line:
                    return line.split('dev')[1].split()[0]
        except Exception:
            pass
        return conf.iface

    def get_interface(self) -> str:
        return self.interface

    def get_my_ip(self) -> str:
        from scapy.all import get_if_addr
        return get_if_addr(self.interface)

    def get_my_mac(self) -> str:
        from scapy.all import get_if_hwaddr
        return get_if_hwaddr(self.interface)

    def detect_gateway_ip(self) -> str:
        try:
            out = subprocess.check_output("ip route", shell=True).decode()
            for line in out.split('\n'):
                if 'default' in line:
                    return line.split('via')[1].split()[0]
        except Exception:
            pass
        return conf.route.route("0.0.0.0")[2]

    def resolve_mac(self, ip: str, timeout: float = 2.0, retry: int = 3) -> Optional[str]:
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                          timeout=timeout, retry=retry, verbose=False)
            for _, rcv in ans:
                return rcv[Ether].src
        except Exception as e:
            log_warn(f"Failed to resolve MAC for {ip}: {e}")
        return None

    def scan_local_network(self) -> List[Tuple[str, str]]:
        """Active scanner utilizing ARP requests to discover alive MAC/IP pairs on local network."""
        my_ip = self.get_my_ip()
        if not my_ip:
            return []
        
        # Determine local range
        ip_parts = my_ip.split('.')
        if len(ip_parts) != 4:
            return []
        network_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."
        
        discovered = []
        log_info(f"Scanning subnet {network_prefix}0/24...")
        # Batch requests to speed up scanning
        ips = [f"{network_prefix}{i}" for i in range(1, 255) if f"{network_prefix}{i}" != my_ip]
        
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips), timeout=1.5, verbose=False)
            for _, rcv in ans:
                discovered.append((rcv[ARP].psrc, rcv[ARP].hwsrc))
        except Exception as e:
            log_err(f"Network discovery error: {e}")
            
        return discovered

    def lock_arp_entry(self, ip: str, mac: str):
        """Creates a static permanent entry in the OS kernel ARP cache table."""
        log_info(f"Injecting permanent static neighbor entry: {ip} -> {mac}")
        subprocess.call(
            f"ip neigh replace {ip} lladdr {mac} dev {self.interface} nud permanent",
            shell=True, stderr=subprocess.DEVNULL
        )

    def unlock_arp_entry(self, ip: str):
        """Unlocks an ARP cache entry returning it to dynamic reachable status."""
        log_info(f"Releasing dynamic neighbor entry: {ip}")
        subprocess.call(
            f"ip neigh replace {ip} dev {self.interface} nud reachable",
            shell=True, stderr=subprocess.DEVNULL
        )

    def apply_arptables_rules(self, my_ip: str, my_mac: str, gw_ip: str, gw_mac: str):
        """Applies arptables filters to block spoofed gateway and duplicate own IP ARP frames."""
        log_info("Configuring arptables kernel packet filtering...")
        subprocess.call(["arptables", "-F"], stderr=subprocess.DEVNULL)
        # Block ARP frames alleging gateway IP from mismatched MAC
        subprocess.call(
            f"arptables -A INPUT -s {gw_ip} --src-mac ! {gw_mac} -j DROP",
            shell=True, stderr=subprocess.DEVNULL
        )
        # Block ARP frames pretending to be our own IP (IP conflict attack mitigation)
        subprocess.call(
            f"arptables -A INPUT -s {my_ip} -j DROP",
            shell=True, stderr=subprocess.DEVNULL
        )

    def clear_arptables_rules(self):
        """Flushes all arptables filtering rules."""
        subprocess.call(["arptables", "-F"], stderr=subprocess.DEVNULL)

    def send_arp_restoration_blasts(self, my_ip: str, my_mac: str, gw_ip: str, gw_mac: str, count: int = 5):
        """Sends broadcast restoration ARP replies to correct any poisoned devices."""
        log_info(f"Blasting {count} restoration frames to refresh network routing mappings...")
        send(ARP(op=2, pdst=gw_ip, psrc=my_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=my_mac), count=count, verbose=False)
        send(ARP(op=2, pdst=my_ip, psrc=gw_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gw_mac), count=count, verbose=False)
