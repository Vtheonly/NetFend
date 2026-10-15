"""Dashboard authentication (ADR-004).

- Token file: /var/lib/netfend/dashboard.token (0600, auto-generated)
- GET (read-only telemetry): allowed from localhost without token when
  `dashboard.allow_local_readonly` is true (default); remote GET always
  requires token
- POST (state-changing): ALWAYS requires X-NetFend-Token + per-session
  CSRF token issued via /api/session
- Login attempts rate-limited per source address
- The token value itself is never returned by any endpoint
"""
import hmac
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Dict, Optional

from netfend.utils.config import DASHBOARD_TOKEN_FILE, cfg
from netfend.utils.logging import log_info, log_warn

_SESSION_TTL_S = 3600
_MAX_SESSIONS = 64


class DashboardAuth:
    def __init__(self, token_path: Path = None):
        self.token_path = Path(token_path) if token_path else DASHBOARD_TOKEN_FILE
        self._token: Optional[bytes] = None
        self._sessions: Dict[str, float] = {}   # csrf_token -> expiry
        self._login_attempts: Dict[str, list] = {}  # ip -> [timestamps]
        self._lock = threading.Lock()

    # -- token management -----------------------------------------------------
    def ensure_token(self) -> None:
        """Load or create the dashboard token file (0600)."""
        if self._token is not None:
            return
        try:
            self.token_path.parent.mkdir(parents=True, exist_ok=True)
            if self.token_path.exists():
                data = self.token_path.read_bytes().strip()
                if len(data) >= 16:
                    self._token = data
                    return
            token = secrets.token_urlsafe(32).encode()
            fd = os.open(self.token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(token)
            self._token = token
            log_info(f"Dashboard token generated: {self.token_path} (mode 0600)")
        except OSError as e:
            log_warn(f"Dashboard token unavailable: {e} — state-changing API disabled")

    def token_is_set(self) -> bool:
        self.ensure_token()
        return self._token is not None

    def check_token(self, presented: str) -> bool:
        """Constant-time comparison of the presented token."""
        self.ensure_token()
        if not self._token or not presented:
            return False
        try:
            return hmac.compare_digest(self._token, presented.encode())
        except (AttributeError, UnicodeEncodeError):
            return False

    # -- sessions / CSRF ---------------------------------------------------------
    def new_session(self) -> Optional[str]:
        """Create a session, returns its CSRF token."""
        with self._lock:
            now = time.time()
            # reap expired
            self._sessions = {k: v for k, v in self._sessions.items() if v > now}
            if len(self._sessions) >= _MAX_SESSIONS:
                return None
            csrf = secrets.token_urlsafe(24)
            self._sessions[csrf] = now + _SESSION_TTL_S
            return csrf

    def check_csrf(self, csrf: str) -> bool:
        if not csrf:
            return False
        with self._lock:
            expiry = self._sessions.get(csrf)
            if expiry is None or expiry < time.time():
                return False
            return True

    def drop_session(self, csrf: str) -> None:
        with self._lock:
            self._sessions.pop(csrf, None)

    # -- rate limiting -------------------------------------------------------------
    def login_rate_ok(self, client_ip: str) -> bool:
        limit = cfg("dashboard", "login_rate_per_min", 10)
        now = time.time()
        with self._lock:
            attempts = [t for t in self._login_attempts.get(client_ip, []) if now - t < 60]
            if len(attempts) >= limit:
                self._login_attempts[client_ip] = attempts
                return False
            attempts.append(now)
            self._login_attempts[client_ip] = attempts
            return True
