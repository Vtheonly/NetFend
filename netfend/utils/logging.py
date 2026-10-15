"""Logging with rotation and optional colorama (ADR-005: optional deps).

Keeps the original public API (log_info/log_success/log_warn/log_err/
log_alert/log_escalation) so existing callers keep working, but:
- rotating file handler (bounded disk use — audit RC-11)
- colorama optional, ANSI fallback
- console output suppressed when not a TTY (systemd journal gets clean text)
"""
import logging
import sys
from logging.handlers import RotatingFileHandler

from netfend.utils.config import (
    DATA_DIR, LOG_FILE, cfg,
    THREAT_MONITOR, THREAT_SUSPECT, THREAT_HOSTILE, THREAT_CRITICAL,
)

try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:  # ANSI fallback
    HAS_COLORAMA = False

    class _Fore:
        CYAN = GREEN = YELLOW = RED = MAGENTA = WHITE = BRIGHT = ""

    class _Style:
        RESET_ALL = BRIGHT = ""

    Fore, Style = _Fore(), _Style()

_LOGGER_NAME = "netfend"
_logger = logging.getLogger(_LOGGER_NAME)
_console_is_tty = sys.stdout.isatty()
_configured = False


def setup_logging(level: str = None) -> logging.Logger:
    """Idempotent logging setup. Called by engine/CLI entry points."""
    global _configured
    if _configured:
        return _logger
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            str(LOG_FILE),
            maxBytes=cfg("general", "log_max_bytes", 2_000_000),
            backupCount=cfg("general", "log_backups", 3),
        )
        handler.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        _logger.addHandler(handler)
    except OSError as e:
        # No writable data dir: keep console-only logging, never crash.
        print(f"[netfend] WARNING: file logging unavailable ({e}); console only", file=sys.stderr)
    _logger.setLevel((level or cfg("general", "log_level", "INFO")).upper())
    _configured = True
    return _logger


def _console(msg: str) -> None:
    if _console_is_tty:
        print(msg)


def log_info(msg: str):
    setup_logging()
    _logger.info(msg)
    _console(f"[{Fore.CYAN}NetFend{Style.RESET_ALL}] {msg}")


def log_success(msg: str):
    setup_logging()
    _logger.info(f"SUCCESS: {msg}")
    _console(f"[{Fore.GREEN}OK{Style.RESET_ALL}] {msg}")


def log_warn(msg: str):
    setup_logging()
    _logger.warning(msg)
    _console(f"[{Fore.YELLOW}WARNING{Style.RESET_ALL}] {msg}")


def log_err(msg: str):
    setup_logging()
    _logger.error(msg)
    _console(f"[{Fore.RED}ERROR{Style.RESET_ALL}] {msg}")


def log_alert(msg: str):
    setup_logging()
    _logger.warning(f"ALERT: {msg}")
    _console(f"[{Fore.RED}{Style.BRIGHT}ALERT{Style.RESET_ALL}] {msg}")


def log_escalation(mac: str, old_level: str, new_level: str, reason: str = "attack pattern escalation"):
    setup_logging()
    colors = {
        THREAT_MONITOR: Fore.WHITE,
        THREAT_SUSPECT: Fore.YELLOW,
        THREAT_HOSTILE: Fore.RED,
        THREAT_CRITICAL: f"{Fore.RED}{Style.BRIGHT}",
    }
    new_c = colors.get(new_level, Fore.WHITE)
    msg = f"[ESCALATION] {mac}: {old_level} -> {new_level} ({reason})"
    _logger.info(f"ESCALATION: {mac} {old_level} -> {new_level} ({reason})")
    _console(f"[{Fore.MAGENTA}THREAT{Style.RESET_ALL}] [ESCALATION] {mac}: "
             f"{old_level} -> {new_c}{new_level}{Style.RESET_ALL} ({reason})")
