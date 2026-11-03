"""Authentication and account lifecycle shared by the API, the portal and the simulation."""
import secrets
from dataclasses import dataclass
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import controls
from backend.catalog import managed_resources
from backend.database import utcnow
from backend.errors import ServiceError
from backend.event_service import has_access, record_event, write_audit
from backend.models import AccessPermission, Employee, EmployeeSession, employee_code_for
from backend.security import create_session, hash_password, needs_rehash, verify_password


@lru_cache
def _dummy_hash() -> str:
    """A valid hash of a random value, checked for unknown identifiers so they take as long as a real wrong password."""
    return hash_password(secrets.token_urlsafe(16))


@dataclass
class LoginResult:
    token: str
    session: EmployeeSession
    employee: Employee


def find_employee(db: Session, identifier: str) -> Employee | None:
    """Look up by employee ID (e.g. EMP-1001); the username is also accepted."""
    ident = identifier.strip()
    return db.scalar(
        select(Employee).where((Employee.employee_code == ident.upper()) | (Employee.username == ident.lower()))
    )


def authenticate(
    db: Session,
    identifier: str,
    password: str,
    *,
    ip: str,
    device_info: str | None = None,
    synthetic: bool = False,
    scenario: str | None = None,
    details: dict | None = None,
) -> LoginResult:
    """Verify credentials, open a session and record the login / failed-login event."""
    employee = find_employee(db, identifier)
    if employee is None:
        verify_password(password, _dummy_hash())  # equalise timing for unknown identifiers
        write_audit(db, "login_unknown_identifier", ip=ip, details={"identifier": identifier[:64]})
        db.commit()
        raise ServiceError(401, "Invalid employee ID or password")

    context = dict(source_ip=ip, device_info=device_info, is_synthetic=synthetic, scenario=scenario)
    if controls.is_ip_blocked(db, ip):
        record_event(db, employee, "login_failed", outcome="denied", details={**(details or {}), "reason": "ip_blocked"}, **context)
        raise ServiceError(403, "Access from this network address is blocked")
    if not verify_password(password, employee.password_hash):
        record_event(db, employee, "login_failed", outcome="failure", details={**(details or {}), "reason": "bad_password"}, **context)
        raise ServiceError(401, "Invalid employee ID or password")

    if employee.status != "active":
        record_event(db, employee, "login_failed", outcome="denied", details={**(details or {}), "reason": "account_locked"}, **context)
        raise ServiceError(403, "Account is locked. Contact the security team.")

    token, session = create_session(db, employee, ip, device_info, synthetic)
    if needs_rehash(employee.password_hash):             # upgrade legacy / weaker hashes now that the password is known
        employee.password_hash = hash_password(password)
    employee.last_login_at = utcnow()
    record_event(db, employee, "login", session=session, details=details, commit=False, **context)
    write_audit(db, "login_success", actor_id=employee.id, target_type="session", target_id=session.id, ip=ip)
    db.commit()
    return LoginResult(token=token, session=session, employee=employee)


def create_account(
    db: Session,
    creator: Employee,
    session: EmployeeSession,
    *,
    username: str,
    full_name: str,
    password: str,
    ip: str,
    device_info: str | None = None,
    scenario: str | None = None,
    extra: dict | None = None,
) -> Employee:
    """Create a privileged account (write access to every managed resource).

    Requires write access to the IT admin console. The attempt is always recorded as an
    administrative_action event, whether it is permitted or not.
    """
    synthetic = session.is_synthetic
    context = dict(source_ip=ip, device_info=device_info, session=session, scenario=scenario,
                   resource="it-admin-console")
    base = {**(extra or {}), "action": "create_privileged_account", "requested_username": username}
    if not has_access(db, creator.id, "it-admin-console", "export"):
        record_event(db, creator, "administrative_action", outcome="denied", details={**base, "reason": "no_admin_console_access"}, **context)
        raise ServiceError(403, "You do not have permission to create accounts")
    if db.scalar(select(Employee.id).where(Employee.username == username)):
        raise ServiceError(409, "Username already exists")

    account = Employee(
        username=username, full_name=full_name, email=f"{username}@westbridgebank.test",
        department="IT", job_role="Privileged Service Account", role="employee", status="active",
        password_hash=hash_password(password), known_ips=[], is_synthetic=synthetic, created_by_id=creator.id,
    )
    account.permissions = [AccessPermission(resource=r, access_level="write") for r in managed_resources()]
    db.add(account)
    db.flush()
    account.employee_code = employee_code_for(account.id, account.role)
    record_event(
        db, creator, "administrative_action", outcome="success",
        details={**base, "new_account": username, "new_account_id": account.employee_code, "privilege": "all_resources_write"},
        commit=False, **context,
    )
    write_audit(db, "account_created", actor_id=creator.id, target_type="employee", target_id=account.id, ip=ip,
                details={"username": username, "privileged": True, "synthetic": synthetic})
    db.commit()
    return account
