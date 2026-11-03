import hashlib
import hmac
import ipaddress
import secrets
from base64 import b64decode, b64encode
from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.database import get_db, utcnow
from backend.models import Employee, EmployeeSession

_ALGORITHM = "pbkdf2_sha256"
_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str, iterations: int | None = None) -> str:
    iterations = iterations or get_settings().password_hash_iterations
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{_ALGORITHM}${iterations}${b64encode(salt).decode()}${b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt, expected = stored.split("$")
        if algorithm != _ALGORITHM:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), b64decode(salt), int(iterations))
        return hmac.compare_digest(digest, b64decode(expected))
    except (ValueError, TypeError):
        return False


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Only an HMAC of the session token is stored, so a database leak does not expose live sessions."""
    return hmac.new(get_settings().secret_key.encode(), token.encode(), hashlib.sha256).hexdigest()


def create_session(
    db: Session, employee: Employee, ip: str, device_info: str | None = None, synthetic: bool = False
) -> tuple[str, EmployeeSession]:
    token = generate_token()
    session = EmployeeSession(
        employee_id=employee.id,
        token_hash=hash_token(token),
        ip_address=ip,
        device_info=device_info,
        is_synthetic=synthetic,
        expires_at=utcnow() + timedelta(minutes=get_settings().session_ttl_minutes),
    )
    db.add(session)
    db.flush()
    return token, session


def normalize_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def is_trusted_frontend(request: Request) -> bool:
    """True when the request carries the shared key that only our own dashboards hold (TRUSTED_FRONTEND_KEY)."""
    expected = get_settings().trusted_frontend_key
    provided = request.headers.get("x-frontend-key", "")
    return bool(expected) and hmac.compare_digest(provided.encode(), expected.encode())


def resolve_ip(request: Request, employee: Employee | None = None) -> str:
    """Source IP as seen by the backend; clients cannot supply it.

    Everything runs on one machine in the local demo, so loopback connections are attributed to the
    employee's registered workstation address (MAP_LOOPBACK_TO_WORKSTATION=true). When the dashboards run on a
    different host (for example Streamlit Cloud calling a hosted API) the backend only sees the dashboard
    server's address, so a request that proves it comes from our own dashboards (X-Frontend-Key matching
    TRUSTED_FRONTEND_KEY) is attributed the same way. Any other peer address is recorded as-is, and
    X-Forwarded-For is never used.
    """
    host = normalize_ip(request.client.host if request.client else None)
    is_local = host is None or ipaddress.ip_address(host).is_loopback
    has_workstation = employee is not None and bool(employee.known_ips)
    if has_workstation and is_local and get_settings().map_loopback_to_workstation:
        return employee.known_ips[0]
    if has_workstation and is_trusted_frontend(request):
        return employee.known_ips[0]
    return host or "0.0.0.0"


def device_info(request: Request) -> str:
    """Descriptive device string from the client; informational only and sanitised."""
    raw = request.headers.get("x-device-info") or request.headers.get("user-agent") or "unknown"
    return "".join(ch for ch in raw if ch.isprintable())[:200] or "unknown"


@dataclass
class AuthContext:
    employee: Employee
    session: EmployeeSession

    @property
    def is_admin(self) -> bool:
        return self.employee.role == "security_admin"


def get_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> AuthContext:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Invalid or expired session", headers={"WWW-Authenticate": "Bearer"}
    )
    if credentials is None:
        raise unauthorized
    session = db.scalar(select(EmployeeSession).where(EmployeeSession.token_hash == hash_token(credentials.credentials)))
    if session is None or session.revoked_at is not None or session.expires_at <= utcnow():
        raise unauthorized
    employee = session.employee
    if employee.status != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is locked")
    from backend import controls

    if controls.is_ip_blocked(db, resolve_ip(request, employee)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Access from this network address is blocked")
    return AuthContext(employee=employee, session=session)


def require_admin(auth: AuthContext = Depends(get_auth)) -> AuthContext:
    if not auth.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Security administrator role required")
    return auth
