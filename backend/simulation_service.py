"""Attack simulation for local demonstrations.

Every step goes through the same authentication, permission checks, event collection and detection
engine as a normal employee. Everything it creates is flagged `is_synthetic` and can be reset.
"""
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session

from backend import response_service
from backend.auth_service import authenticate, create_account
from backend.config import get_settings
from backend.database import utcnow
from backend.errors import ServiceError
from backend.event_service import access_resource, record_event, write_audit
from backend.models import (
    AttackInvestigation,
    ContainmentAction,
    Employee,
    EmployeeSession,
    RiskAssessment,
    SecurityAlert,
    SecurityEvent,
)

SIM_DEVICE = "SimulatedAttackerToolkit/1.0 (Linux x86_64; synthetic)"
DEFAULT_SOURCE_IP = "185.220.101.45"  # documentation-style external address, not in any employee's known list
EXPORT_RECORDS = 25_000
PROBE_RESOURCES = ["hr-records", "payroll-records", "it-admin-console", "audit-reports", "loan-applications"]
EXFIL_DESTINATION = "files.exfil-sim.example.invalid"
EXPORT_PRIORITY = ["customer-accounts", "payroll-records", "hr-records", "loan-applications", "financial-reports",
                   "trading-reports", "audit-reports", "source-code-repo", "it-admin-console"]

STEPS = [
    {"id": "unfamiliar_login", "label": "Login from unfamiliar IP",
     "description": "Signs in as the selected employee with stolen credentials from the chosen source IP."},
    {"id": "restricted_access", "label": "Access restricted resources",
     "description": "Probes HR, payroll, IT admin, audit and lending data; the backend permission check decides each result."},
    {"id": "large_export", "label": "Large record export",
     "description": f"Exports or downloads {EXPORT_RECORDS:,} records from the most sensitive resource the account can reach."},
    {"id": "admin_login_failures", "label": "Failed administrator logins",
     "description": "Five failed attempts to authenticate to the administrator console."},
    {"id": "create_privileged_account", "label": "Privileged account creation",
     "description": "Tries to create a privileged account; only permitted if the compromised user has IT admin console write access."},
    {"id": "privileged_login", "label": "Login with new privileged account",
     "description": "Signs in with the account created in the previous step."},
    {"id": "external_transfer", "label": "External data transfer",
     "description": "Sends the collected records to an external (synthetic, non-routable) destination."},
]
STEP_IDS = [s["id"] for s in STEPS]

SCENARIOS = [
    {"id": "it_admin_full_chain", "name": "Compromised IT administrator - full attack chain",
     "default_target": "david.kumar", "steps": STEP_IDS,
     "description": "The IT administrator can create privileged accounts, so every stage of the chain succeeds."},
    {"id": "finance_data_theft", "name": "Compromised finance analyst - data theft",
     "default_target": "alice.morgan",
     "steps": ["unfamiliar_login", "restricted_access", "large_export", "admin_login_failures", "external_transfer"],
     "description": "A standard employee account: restricted access is denied by the backend, exports are limited to its own data."},
]
SCENARIO_IDS = {s["id"] for s in SCENARIOS}


class _Sim:
    def __init__(self, db: Session, admin: Employee, target: Employee, ip: str, scenario: str):
        self.db, self.admin, self.target, self.ip, self.scenario = db, admin, target, ip, scenario

    def meta(self, step: str) -> dict:
        return {"sim_step": step, "scenario": self.scenario, "simulated_by": self.admin.username}


def _active_session(sim: _Sim, employee: Employee) -> EmployeeSession | None:
    if employee.status != "active":
        raise ServiceError(403, f"Account {employee.username} is locked - containment is in effect")
    return sim.db.scalar(
        select(EmployeeSession).where(
            EmployeeSession.employee_id == employee.id, EmployeeSession.is_synthetic.is_(True),
            EmployeeSession.revoked_at.is_(None), EmployeeSession.expires_at > utcnow(),
        ).order_by(EmployeeSession.id.desc())
    )


def _need_session(sim: _Sim, employee: Employee) -> EmployeeSession:
    session = _active_session(sim, employee)
    if session is None:
        raise ServiceError(409, f"No active simulated session for {employee.username}: run the login step first "
                                "(or the session was revoked by containment)")
    return session


def _privileged_account(sim: _Sim) -> Employee | None:
    return sim.db.scalar(
        select(Employee).where(Employee.created_by_id == sim.target.id, Employee.is_synthetic.is_(True))
        .order_by(Employee.id.desc())
    )


def _best_resource(employee: Employee) -> tuple[str, str]:
    """The most valuable data resource the account can reach (write access allows a full export)."""
    def rank(permission) -> tuple[int, int]:
        order = EXPORT_PRIORITY.index(permission.resource) if permission.resource in EXPORT_PRIORITY else len(EXPORT_PRIORITY)
        return order, permission.access_level != "write"

    perms = sorted(employee.permissions, key=rank)
    if not perms:
        raise ServiceError(409, f"{employee.username} has no resource access to export from")
    top = perms[0]
    return top.resource, "export" if top.access_level == "write" else "download"


def _step_unfamiliar_login(sim: _Sim) -> dict:
    result = authenticate(
        sim.db, sim.target.employee_code, get_settings().demo_employee_password, ip=sim.ip, device_info=SIM_DEVICE,
        synthetic=True, scenario=sim.scenario, details=sim.meta("unfamiliar_login"),
    )
    return {"status": "completed", "detail": f"Signed in as {sim.target.username} from {sim.ip} (session {result.session.id})"}


def _step_restricted_access(sim: _Sim) -> dict:
    session = _need_session(sim, sim.target)
    outcomes = []
    for resource in PROBE_RESOURCES:
        _, permitted = access_resource(
            sim.db, sim.target, resource, "view", source_ip=sim.ip, session=session, record_count=25,
            details=sim.meta("restricted_access"), device_info=SIM_DEVICE, is_synthetic=True, scenario=sim.scenario,
        )
        outcomes.append(f"{resource}: {'granted' if permitted else 'denied'}")
    return {"status": "completed", "detail": "; ".join(outcomes)}


def _step_large_export(sim: _Sim) -> dict:
    session = _need_session(sim, sim.target)
    resource, action = _best_resource(sim.target)
    _, permitted = access_resource(
        sim.db, sim.target, resource, action, source_ip=sim.ip, session=session, record_count=EXPORT_RECORDS,
        details=sim.meta("large_export"), device_info=SIM_DEVICE, is_synthetic=True, scenario=sim.scenario,
    )
    return {"status": "completed" if permitted else "denied",
            "detail": f"{action} of {EXPORT_RECORDS:,} records from {resource}: {'granted' if permitted else 'denied'}"}


def _step_admin_login_failures(sim: _Sim) -> dict:
    session = _need_session(sim, sim.target)
    for attempt in range(1, 6):
        record_event(
            sim.db, sim.target, "login_failed", source_ip=sim.ip, resource="it-admin-console", outcome="failure",
            details={**sim.meta("admin_login_failures"), "auth_target": "administrator_console", "attempt": attempt,
                     "reason": "bad_password"},
            session=session, device_info=SIM_DEVICE, scenario=sim.scenario,
        )
    return {"status": "completed", "detail": "5 failed administrator console logins recorded"}


def _step_create_privileged_account(sim: _Sim) -> dict:
    session = _need_session(sim, sim.target)
    count = sim.db.scalar(select(func.count(Employee.id)).where(Employee.is_synthetic.is_(True))) or 0
    username = f"svc.backup{count + 1:02d}"
    try:
        account = create_account(
            sim.db, sim.target, session, username=username, full_name="Backup Service Account (synthetic)",
            password=get_settings().simulation_privileged_password, ip=sim.ip, device_info=SIM_DEVICE,
            scenario=sim.scenario, extra=sim.meta("create_privileged_account"),
        )
    except ServiceError as exc:
        if exc.status_code != 403:
            raise
        return {"status": "denied", "detail": f"Backend denied account creation for {sim.target.username}: {exc.message}"}
    return {"status": "completed", "detail": f"Created privileged account {account.username} ({account.employee_code})"}


def _step_privileged_login(sim: _Sim) -> dict:
    account = _privileged_account(sim)
    if account is None:
        raise ServiceError(409, "No privileged account exists yet: run the account creation step first")
    result = authenticate(
        sim.db, account.employee_code, get_settings().simulation_privileged_password, ip=sim.ip,
        device_info=SIM_DEVICE, synthetic=True, scenario=sim.scenario, details=sim.meta("privileged_login"),
    )
    return {"status": "completed", "detail": f"Signed in as {account.username} from {sim.ip} (session {result.session.id})"}


def _step_external_transfer(sim: _Sim) -> dict:
    account = _privileged_account(sim)
    actor, session = sim.target, None
    if account is not None and account.status == "active":
        session = _active_session(sim, account)
        actor = account if session else sim.target
    session = session or _need_session(sim, sim.target)
    resource, _ = _best_resource(actor)
    record_event(
        sim.db, actor, "external_transfer", source_ip=sim.ip, resource=resource, outcome="success",
        details={**sim.meta("external_transfer"), "destination": EXFIL_DESTINATION, "protocol": "https",
                 "transfer_status": "confirmed"},
        session=session, device_info=SIM_DEVICE, records_accessed=EXPORT_RECORDS, records_downloaded=EXPORT_RECORDS,
        is_synthetic=True, scenario=sim.scenario,
    )
    return {"status": "completed",
            "detail": f"{EXPORT_RECORDS:,} records from {resource} sent to {EXFIL_DESTINATION} as {actor.username}"}


_HANDLERS = {
    "unfamiliar_login": _step_unfamiliar_login,
    "restricted_access": _step_restricted_access,
    "large_export": _step_large_export,
    "admin_login_failures": _step_admin_login_failures,
    "create_privileged_account": _step_create_privileged_account,
    "privileged_login": _step_privileged_login,
    "external_transfer": _step_external_transfer,
}


def run_step(db: Session, admin: Employee, target: Employee, step: str, ip: str, scenario: str) -> dict:
    if step not in _HANDLERS:
        raise ServiceError(422, f"Unknown simulation step '{step}'")
    before = db.scalar(select(func.max(SecurityEvent.id))) or 0
    sim = _Sim(db, admin, target, ip, scenario)
    try:
        outcome = _HANDLERS[step](sim)
    except ServiceError as exc:
        db.rollback()
        outcome = {"status": "blocked", "detail": exc.message}
    write_audit(db, "simulation_step", actor_id=admin.id, target_type="employee", target_id=target.id,
                details={"step": step, "scenario": scenario, "source_ip": ip, "status": outcome["status"]})
    db.commit()
    events = list(db.scalars(select(SecurityEvent.id).where(SecurityEvent.id > before, SecurityEvent.is_synthetic.is_(True))))
    return {"step": step, **outcome, "event_ids": events}


def run_scenario(db: Session, admin: Employee, target: Employee, ip: str, scenario: str) -> list[dict]:
    steps = next(s["steps"] for s in SCENARIOS if s["id"] == scenario)
    return [run_step(db, admin, target, step, ip, scenario) for step in steps]


def status(db: Session) -> dict:
    synthetic_events = db.execute(
        select(SecurityEvent.details, SecurityEvent.scenario).where(SecurityEvent.is_synthetic.is_(True))
    ).all()
    steps = {d.get("sim_step") for d, _ in synthetic_events if d and d.get("sim_step")}
    accounts = db.execute(select(Employee.employee_code, Employee.username).where(Employee.is_synthetic.is_(True))).all()
    return {
        "synthetic_events": len(synthetic_events),
        "steps_executed": [s for s in STEP_IDS if s in steps],
        "scenarios": sorted({sc for _, sc in synthetic_events if sc}),
        "synthetic_accounts": [{"employee_id": c, "username": u} for c, u in accounts],
        "active_synthetic_sessions": db.scalar(select(func.count(EmployeeSession.id)).where(
            EmployeeSession.is_synthetic.is_(True), EmployeeSession.revoked_at.is_(None),
            EmployeeSession.expires_at > utcnow())) or 0,
    }


def reset(db: Session, admin: Employee) -> dict:
    """Remove everything the simulation created and undo containment applied to the affected employees."""
    event_ids = list(db.scalars(select(SecurityEvent.id).where(SecurityEvent.is_synthetic.is_(True))))
    synthetic_accounts = set(db.scalars(select(Employee.id).where(Employee.is_synthetic.is_(True))))
    affected = set(db.scalars(select(SecurityEvent.employee_id).where(SecurityEvent.is_synthetic.is_(True))))
    first_ts = db.scalar(select(func.min(SecurityEvent.timestamp)).where(SecurityEvent.is_synthetic.is_(True)))
    investigation_ids = list(db.scalars(select(AttackInvestigation.id).where(AttackInvestigation.is_synthetic.is_(True))))

    real_affected = [db.get(Employee, i) for i in affected - synthetic_accounts]
    restored = 0
    for employee in real_affected:
        try:
            response_service.restore_employee(db, employee)
            restored += 1
        except ServiceError:
            pass

    removed: dict[str, int] = {}
    if event_ids or synthetic_accounts:
        assessment_filter = [RiskAssessment.event_id.in_(event_ids)] if event_ids else []
        if first_ts is not None and affected:
            assessment_filter.append((RiskAssessment.employee_id.in_(affected)) & (RiskAssessment.created_at >= first_ts))
        removed["risk_assessments"] = db.execute(delete(RiskAssessment).where(or_(*assessment_filter))).rowcount if assessment_filter else 0
    removed["alerts"] = db.execute(delete(SecurityAlert).where(SecurityAlert.is_synthetic.is_(True))).rowcount
    containment_filter = [ContainmentAction.employee_id.in_(synthetic_accounts)] if synthetic_accounts else []
    if investigation_ids:
        containment_filter.append(ContainmentAction.investigation_id.in_(investigation_ids))
    removed["containment_actions"] = (
        db.execute(delete(ContainmentAction).where(or_(*containment_filter))).rowcount if containment_filter else 0
    )
    removed["investigations"] = db.execute(delete(AttackInvestigation).where(AttackInvestigation.is_synthetic.is_(True))).rowcount
    removed["events"] = db.execute(delete(SecurityEvent).where(SecurityEvent.is_synthetic.is_(True))).rowcount
    removed["sessions"] = db.execute(delete(EmployeeSession).where(EmployeeSession.is_synthetic.is_(True))).rowcount
    removed["accounts"] = db.execute(delete(Employee).where(Employee.is_synthetic.is_(True))).rowcount

    for employee in real_affected:
        last = db.scalar(select(func.max(SecurityEvent.timestamp)).where(
            SecurityEvent.employee_id == employee.id, SecurityEvent.event_type == "login"))
        db.execute(update(Employee).where(Employee.id == employee.id).values(last_login_at=last))

    write_audit(db, "simulation_reset", actor_id=admin.id, details={**removed, "employees_restored": restored})
    db.commit()
    db.expire_all()
    return {**removed, "employees_restored": restored}
