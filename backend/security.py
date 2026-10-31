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


def create_session(db: Session, employee: Employee, ip: str) -> tuple[str, EmployeeSession]:
    token = generate_token()
    session = EmployeeSession(
        employee_id=employee.id,
        token_hash=hash_token(token),
        ip_address=ip,
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


def resolve_ip(request: Request, override: str | None = None) -> str:
    """Client IP. A caller-supplied IP is honoured only when simulation is enabled (demo/testing)."""
    if override and get_settings().allow_simulated_source_ip:
        return override
    host = request.client.host if request.client else None
    return normalize_ip(host) or "0.0.0.0"


@dataclass
class AuthContext:
    employee: Employee
    session: EmployeeSession

    @property
    def is_admin(self) -> bool:
        return self.employee.role == "security_admin"


def get_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer), db: Session = Depends(get_db)
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
    return AuthContext(employee=employee, session=session)


def require_admin(auth: AuthContext = Depends(get_auth)) -> AuthContext:
    if not auth.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Security administrator role required")
    return auth
