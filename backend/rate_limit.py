"""In-memory rate limiting for the login and other sensitive endpoints.

State is per process and lost on restart: adequate for a single-instance demo, not for a scaled deployment (run one
backend worker, or move the counters to a shared store such as Redis). Limits are checked before any expensive work, so
guessing and abuse are slowed down as well as detected. Memory is bounded: expired entries are dropped and the tables
are capped, so a flood of distinct keys cannot exhaust it.
"""
import threading
import time
from collections import deque

from fastapi import HTTPException, status

from backend.config import get_settings

MAX_KEYS = 10_000


def _prune(table: dict, now: float, horizon: float) -> None:
    """Drop entries whose newest timestamp is older than `horizon` seconds; as a last resort drop the oldest ones."""
    if len(table) < MAX_KEYS:
        return
    for key in [k for k, v in table.items() if not v or now - v[-1] > horizon]:
        table.pop(key, None)
    while len(table) >= MAX_KEYS:
        table.pop(next(iter(table)))


class FailureThrottle:
    """Counts failures per key; `max_attr` failures within `window_attr` seconds locks the key for that long."""

    def __init__(self, max_attr: str, window_attr: str) -> None:
        self._max_attr, self._window_attr = max_attr, window_attr
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
        """Count a failure. Returns True when this failure starts a lockout."""
        s = get_settings()
        limit, window = getattr(s, self._max_attr), getattr(s, self._window_attr)
        key, now = self._key(identifier), time.monotonic()
        with self._lock:
            _prune(self._failures, now, window)
            window_hits = self._failures.setdefault(key, deque())
            window_hits.append(now)
            while window_hits and now - window_hits[0] > window:
                window_hits.popleft()
            if len(window_hits) >= limit and key not in self._locked_until:
                self._locked_until[key] = now + window
                window_hits.clear()
                return True
            return False

    def record_success(self, identifier: str) -> None:
        with self._lock:
            self._failures.pop(self._key(identifier), None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._locked_until.clear()


LoginThrottle = FailureThrottle
login_throttle = FailureThrottle("login_max_failures", "login_lockout_seconds")          # per employee identifier
login_ip_throttle = FailureThrottle("login_ip_max_failures", "login_ip_window_seconds")  # per source address


class ActionLimiter:
    """Sliding-window cap on containment requests per administrator."""

    def __init__(self) -> None:
        self._hits: dict[int, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, admin_id: int) -> int:
        """Record a request. Returns 0 if allowed, otherwise the seconds to wait."""
        limit, now = get_settings().containment_max_per_minute, time.monotonic()
        with self._lock:
            _prune(self._hits, now, 60)
            hits = self._hits.setdefault(admin_id, deque())
            while hits and now - hits[0] > 60:
                hits.popleft()
            if len(hits) >= limit:
                return int(60 - (now - hits[0])) + 1
            hits.append(now)
            return 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


containment_limiter = ActionLimiter()


class RouteLimiter:
    """Sliding one-minute window per (route name, caller)."""

    def __init__(self) -> None:
        self._hits: dict[tuple[str, int], deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, name: str, caller: int, limit: int) -> int:
        now = time.monotonic()
        with self._lock:
            _prune(self._hits, now, 60)
            hits = self._hits.setdefault((name, caller), deque())
            while hits and now - hits[0] > 60:
                hits.popleft()
            if len(hits) >= limit:
                return int(60 - (now - hits[0])) + 1
            hits.append(now)
            return 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


route_limiter = RouteLimiter()
TIERS = {"sensitive": "rate_limit_sensitive_per_minute", "heavy": "rate_limit_heavy_per_minute",
         "employee": "rate_limit_employee_per_minute"}


def enforce(name: str, caller_id: int, tier: str) -> None:
    """Raise HTTP 429 with a Retry-After header when the caller exceeded the tier's per-minute limit for this route."""
    s = get_settings()
    if not s.rate_limits_enabled:
        return
    wait = route_limiter.check(name, caller_id, getattr(s, TIERS[tier]))
    if wait:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"Too many requests for this action. Retry in {wait} seconds.", headers={"Retry-After": str(wait)})


def reset_all() -> None:
    for limiter in (login_throttle, login_ip_throttle, containment_limiter, route_limiter):
        limiter.reset()
