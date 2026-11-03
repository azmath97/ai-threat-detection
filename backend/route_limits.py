"""Authorization + rate-limit dependencies for state-changing and expensive routes.

Each factory returns a FastAPI dependency that first enforces authentication and the role on the backend (the UI hiding a
button is never the control), then applies the named per-minute limit for that caller.
"""
from fastapi import Depends

from backend.rate_limit import enforce
from backend.security import AuthContext, get_auth, require_admin


def admin_limited(name: str, tier: str = "sensitive"):
    def dependency(auth: AuthContext = Depends(require_admin)) -> AuthContext:
        enforce(name, auth.employee.id, tier)
        return auth

    return dependency


def employee_limited(name: str, tier: str = "employee"):
    def dependency(auth: AuthContext = Depends(get_auth)) -> AuthContext:
        enforce(name, auth.employee.id, tier)
        return auth

    return dependency
