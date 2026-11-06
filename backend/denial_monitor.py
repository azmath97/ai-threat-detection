"""Observes the real 401 and 403 responses of the API so repeated unauthorised access can be detected.

Pure ASGI middleware, innermost, so it sees only what the application itself refused (not a request the HTTPS or size
middlewares rejected earlier). After the response has been sent it stores one `access_denials` row: the route *template*, the
identifier that was asked for, the trusted client address and, when the bearer token matches a session, the account. It never
reads or stores a request body, a token, or any credential.

Not recorded, on purpose:
* sign-in failures (they have their own record, `auth_attempts`);
* refusals caused by our own enforcement (a locked account, a blocked address, a revoked session of a locked account), which
  would otherwise feed back into the detector that produced them;
* anything beyond DENIAL_RECORD_LIMIT_PER_MINUTE per address, so a flood of refused requests cannot fill the database.
"""
import logging
import time

from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

from backend import auth_response, controls
from backend.auth_policy import get_policy
from backend.database import SessionLocal
from backend.models import EmployeeSession
from backend.security import hash_token, resolve_ip

log = logging.getLogger("auth_defense")
EXCLUDED_PATHS = {"/api/auth/login"}
_budget: dict[str, list] = {}          # address -> [window start, rows stored in that window]


def reset_budget() -> None:
    _budget.clear()


def _within_budget(ip: str, limit: int) -> bool:
    if limit <= 0:
        return True
    now = time.monotonic()
    window = _budget.get(ip)
    if window is None or now - window[0] >= 60:
        if len(_budget) > 5000:                       # bounded memory under a flood of distinct addresses
            _budget.pop(next(iter(_budget)))
        _budget[ip] = [now, 1]
        return True
    window[1] += 1
    return window[1] <= limit


def _bearer(scope) -> str | None:
    for key, value in scope.get("headers", []):
        if key == b"authorization":
            scheme, _, token = value.decode("latin-1").partition(" ")
            return token.strip() if scheme.lower() == "bearer" and token.strip() else None
    return None


def record(scope, status_code: int) -> None:
    policy = get_policy()
    if not policy.enabled:
        return
    request = Request(scope)
    token = _bearer(scope)
    with SessionLocal() as db:
        session = db.scalar(select(EmployeeSession).where(EmployeeSession.token_hash == hash_token(token))) if token else None
        employee = session.employee if session else None
        ip = resolve_ip(request, employee)
        if (employee is not None and employee.status != "active") or controls.is_ip_blocked(db, ip):
            return                                    # our own enforcement, not probing
        if not _within_budget(ip, policy.denial_record_limit_per_minute):
            return
        route = scope.get("route")
        params = scope.get("path_params") or {}
        auth_response.record_denial(
            db, ip=ip, employee=employee, method=scope.get("method", "GET"), route=getattr(route, "path", None) or "(unmatched)",
            object_ref=str(next(iter(params.values()))) if params else None, status_code=status_code)


class AccessDenialMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/api/") or scope["path"] in EXCLUDED_PATHS:
            await self.app(scope, receive, send)
            return
        seen = {"status": 0}

        async def watch(message):
            if message["type"] == "http.response.start":
                seen["status"] = message["status"]
            await send(message)

        await self.app(scope, receive, watch)
        if seen["status"] in (401, 403):
            try:
                await run_in_threadpool(record, scope, seen["status"])
            except Exception:  # noqa: BLE001 - watching must never break a response that has already been sent
                log.exception("could not record a refused request")
