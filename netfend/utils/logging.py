import logging
from datetime import datetime
from colorama import init, Fore, Style
from netfend.utils.config import DATA_DIR, LOG_FILE, THREAT_MONITOR, THREAT_SUSPECT, THREAT_HOSTILE, THREAT_CRITICAL

init(autoreset=True)

# Set up logging to file
DATA_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def log_info(msg: str):
    logging.info(msg)
    print(f"[{Fore.CYAN}NetFend{Style.RESET_ALL}] {msg}")

def log_success(msg: str):
    logging.info(f"SUCCESS: {msg}")
    print(f"[{Fore.GREEN}OK{Style.RESET_ALL}] {msg}")

def log_warn(msg: str):
    logging.warning(msg)
    print(f"[{Fore.YELLOW}WARNING{Style.RESET_ALL}] {msg}")

def log_err(msg: str):
    logging.error(msg)
    print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] {msg}")

def log_alert(msg: str):
    logging.warning(f"ALERT: {msg}")
    print(f"[{Fore.RED}{Style.BRIGHT}⚠ ALERT{Style.RESET_ALL}] {msg}")

def log_escalation(mac: str, old_level: str, new_level: str, reason: str = "attack pattern escalation"):
    colors = {
        THREAT_MONITOR: Fore.WHITE,
        THREAT_SUSPECT: Fore.YELLOW,
        THREAT_HOSTILE: Fore.RED,
        THREAT_CRITICAL: f"{Fore.RED}{Style.BRIGHT}",
    }
    new_c = colors.get(new_level, Fore.WHITE)
    msg = f"[ESCALATION] {mac}: {old_level} → {new_c}{new_level}{Style.RESET_ALL} ({reason})"
    logging.info(f"ESCALATION: {mac} {old_level} -> {new_level} ({reason})")
    print(f"[{Fore.MAGENTA}THREAT{Style.RESET_ALL}] {msg}")
