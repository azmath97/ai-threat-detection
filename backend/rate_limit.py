"""In-memory failed-login throttle (per employee identifier).

State is per process and lost on restart: adequate for a single-instance demo, not for a scaled deployment.
Throttled attempts are rejected before any password check, so guessing is slowed down as well as detected.
"""
import threading
import time
from collections import deque

from backend.config import get_settings


class LoginThrottle:
    def __init__(self) -> None:
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(identifier: str) -> str:
        return identifier.strip().lower()[:64]

    def retry_after(self, identifier: str) -> int:
        """Seconds left on an active lockout, or 0."""
        key = self._key(identifier)
        with self._lock:
            remaining = self._locked_until.get(key, 0.0) - time.monotonic()
            if remaining <= 0:
                self._locked_until.pop(key, None)
                return 0
            return int(remaining) + 1

    def record_failure(self, identifier: str) -> bool:
        """Count a failed login. Returns True when this failure starts a lockout."""
        s = get_settings()
        key, now = self._key(identifier), time.monotonic()
        with self._lock:
            window = self._failures.setdefault(key, deque())
            window.append(now)
            while window and now - window[0] > s.login_lockout_seconds:
                window.popleft()
            if len(window) >= s.login_max_failures and key not in self._locked_until:
                self._locked_until[key] = now + s.login_lockout_seconds
                window.clear()
                return True
            return False

    def record_success(self, identifier: str) -> None:
        with self._lock:
            self._failures.pop(self._key(identifier), None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._locked_until.clear()


login_throttle = LoginThrottle()
