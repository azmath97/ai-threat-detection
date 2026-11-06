"""SOC endpoints for authentication attacks: overview, incidents, evidence, response actions and manual responses.

Security administrators only (enforced here, not by hiding buttons). State-changing routes are rate limited, validated,
audited and idempotent when the caller sends an Idempotency-Key. Everything is enforced inside this application; nothing
here contacts a firewall or any external system, and the wording of every result says so.
"""
import ipaddress
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend import auth_response
from backend.auth_policy import get_policy
from backend.catalog import SEVERITY_LEVELS
from backend.config import get_settings, to_local
from backend.database import get_db, utcnow
from backend.errors import ServiceError
from backend.event_service import write_audit
from backend.models import (
    INCIDENT_KINDS,
    AuthAttempt,
    AuthIncident,
    Employee,
    IpBlock,
    ResponseAction,
)
from backend.route_limits import admin_limited
from backend.security import AuthContext, idempotency_key, require_admin, resolve_ip

router = APIRouter(prefix="/api/soc/auth", tags=["authentication defence"])
_MAX_PAGE = get_settings().max_page_size

SCOPE_NOTICE = ("Enforced inside this application only: locked accounts and blocked addresses are refused by this backend. "
                "Nothing here is a firewall rule or reaches any network device.")
STATUS_LABELS = {"completed": "Applied in this application", "pending_approval": "Awaiting analyst approval",
                 "skipped": "Not applied", "failed": "Failed"}
ACTION_LABELS = {"lock_account": "Lock account", "unlock_account": "Unlock account", "revoke_sessions": "Revoke sessions",
                 "block_ip": "Block address (application level)", "unblock_ip": "Remove address block"}
KIND_LABELS = {"account_brute_force": "Brute force on one account", "credential_stuffing": "Credential stuffing (one address, many accounts)",
               "ip_failure_burst": "Burst of failures from one address", "distributed_account_attack": "One account attacked from many addresses",
               "login_after_failures": "Successful sign-in after repeated failures"}
ACTIVE = ("open", "investigating", "contained")


def _iso(dt) -> dict:
    return {"utc": dt.isoformat() if dt else None, "local": to_local(dt).isoformat() if dt else None}


def _code(db: Session, employee_id: int | None) -> str | None:
    return auth_response.employee_ref(db, employee_id) if employee_id else None


def action_out(db: Session, a: ResponseAction) -> dict:
    return {"id": a.id, "incident_id": a.incident_id, "target": a.target, "action": a.action_type, "action_label": ACTION_LABELS[a.action_type],
            "status": a.status, "status_label": STATUS_LABELS[a.status], "automatic": a.automatic, "policy": a.policy,
            "performed_by": "policy engine" if a.automatic else (_code(db, a.performed_by) or "system"), "reason": a.reason,
            "result": a.result, "details": a.details or {}, "expires_at": _iso(a.expires_at), "created_at": _iso(a.created_at),
            "scope": SCOPE_NOTICE}


def incident_out(db: Session, i: AuthIncident, *, detail: bool = False) -> dict:
    out = {"id": i.id, "kind": i.kind, "kind_label": KIND_LABELS[i.kind], "severity": i.severity, "status": i.status, "title": i.title,
           "source_ip": i.source_ip, "employee_id": _code(db, i.employee_id), "attempts": i.attempts_count,
           "first_seen": _iso(i.first_seen), "last_seen": _iso(i.last_seen), "updated_at": _iso(i.updated_at),
           "actions": len(i.actions), "pending_approval": sum(1 for a in i.actions if a.status == "pending_approval")}
    if detail:
        out |= {"explanation": i.explanation, "evidence": i.evidence or {}, "resolution_note": i.resolution_note,
                "response_history": [action_out(db, a) for a in i.actions], "scope": SCOPE_NOTICE,
                "severity_note": "A rule-based band for this pattern under the configured thresholds. It is not a probability."}
    return out


def attempt_out(db: Session, a: AuthAttempt) -> dict:
    return {"id": a.id, "timestamp": _iso(a.timestamp), "source_ip": a.source_ip, "account": a.subject, "outcome": a.outcome,
            "reason": a.reason, "device": a.device_info}


# ------------------------------------------------------------------------------------------------------------- reads
@router.get("/overview")
def overview(hours: int = Query(24, ge=1, le=24 * 30), _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    auth_response.expire_blocks(db)
    since = utcnow() - timedelta(hours=hours)
    by_outcome = dict(db.execute(select(AuthAttempt.outcome, func.count(AuthAttempt.id)).where(AuthAttempt.timestamp >= since)
                                 .group_by(AuthAttempt.outcome)).all())
    failing_ips = db.scalar(select(func.count(func.distinct(AuthAttempt.source_ip))).where(
        AuthAttempt.timestamp >= since, AuthAttempt.outcome == "failure")) or 0
    by_severity = dict(db.execute(select(AuthIncident.severity, func.count(AuthIncident.id))
                                  .where(AuthIncident.status.in_(ACTIVE)).group_by(AuthIncident.severity)).all())
    locked = db.scalars(select(Employee).where(Employee.status == "locked").order_by(Employee.locked_at.desc())).all()
    blocks = db.scalars(select(IpBlock).where(IpBlock.active.is_(True)).order_by(IpBlock.id.desc())).all()
    pending = db.scalar(select(func.count(ResponseAction.id)).join(AuthIncident, ResponseAction.incident_id == AuthIncident.id)
                        .where(ResponseAction.status == "pending_approval", AuthIncident.status.in_(ACTIVE))) or 0
    policy = get_policy()
    return {
        "window_hours": hours, "scope": SCOPE_NOTICE,
        "attempts": {"total": sum(by_outcome.values()), "success": by_outcome.get("success", 0), "failure": by_outcome.get("failure", 0),
                     "denied": by_outcome.get("denied", 0), "distinct_failing_addresses": failing_ips},
        "active_incidents": {"total": sum(by_severity.values()), **{s: by_severity.get(s, 0) for s in SEVERITY_LEVELS if s != "normal"}},
        "pending_approval": pending,
        "locked_accounts": [{"employee_id": e.employee_code, "name": e.full_name, "reason": e.lock_reason, "locked_at": _iso(e.locked_at),
                             "expires_at": _iso(e.lock_expires_at), "locked_by": e.locked_by,
                             "automatic": (e.locked_by or "").startswith("policy:")} for e in locked],
        "blocked_addresses": [{"ip": b.ip, "source": b.source, "reason": b.reason, "created_at": _iso(b.created_at),
                               "expires_at": _iso(b.expires_at), "incident_id": b.incident_id,
                               "status": "Blocked in this application (not a firewall rule)"} for b in blocks
                              if b.expires_at is None or b.expires_at > utcnow()],
        "policy": {"auto_response": policy.auto_response, "account_lockout_threshold": policy.account_fail_threshold,
                   "account_window_minutes": policy.account_window_minutes, "account_lock_minutes": policy.account_lock_minutes,
                   "known_ip_lockout_threshold": policy.known_ip_fail_threshold, "ip_alert_failures": policy.ip_alert_failures,
                   "ip_alert_window_minutes": policy.ip_alert_window_minutes, "ip_block_threshold": policy.ip_block_threshold,
                   "ip_block_window_minutes": policy.ip_block_window_minutes, "ip_block_minutes": policy.ip_block_minutes,
                   "stuffing_accounts_alert": policy.stuffing_accounts_alert, "stuffing_accounts_critical": policy.stuffing_accounts_critical,
                   "stuffing_window_minutes": policy.stuffing_window_minutes, "max_auto_locks_per_hour": policy.max_auto_locks_per_hour,
                   "max_auto_blocks_per_hour": policy.max_auto_blocks_per_hour,
                   "note": "Starting policy, configurable by environment variables; calibrate against real sign-in traffic."},
    }


@router.get("/incidents")
def incidents(inc_status: str = Query("active", alias="status", pattern="^(active|all|open|investigating|contained|resolved|false_positive)$"),
              severity: str | None = Query(None), kind: str | None = Query(None), ip: str | None = Query(None, max_length=45),
              employee: str | None = Query(None, max_length=16), minutes: int | None = Query(None, ge=1, le=60 * 24 * 90),
              limit: int = Query(100, ge=1, le=_MAX_PAGE), _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    if severity and severity not in SEVERITY_LEVELS:
        raise HTTPException(422, f"severity must be one of {', '.join(SEVERITY_LEVELS)}")
    if kind and kind not in INCIDENT_KINDS:
        raise HTTPException(422, f"kind must be one of {', '.join(INCIDENT_KINDS)}")
    query = select(AuthIncident).order_by(AuthIncident.updated_at.desc(), AuthIncident.id.desc()).limit(limit)
    if inc_status == "active":
        query = query.where(AuthIncident.status.in_(ACTIVE))
    elif inc_status != "all":
        query = query.where(AuthIncident.status == inc_status)
    if severity:
        query = query.where(AuthIncident.severity == severity)
    if kind:
        query = query.where(AuthIncident.kind == kind)
    if ip:
        query = query.where(AuthIncident.source_ip == ip)
    if employee:
        emp_id = db.scalar(select(Employee.id).where(Employee.employee_code == employee.upper()))
        query = query.where(AuthIncident.employee_id == (emp_id or -1))
    if minutes:
        query = query.where(AuthIncident.updated_at >= utcnow() - timedelta(minutes=minutes))
    return {"rows": [incident_out(db, i) for i in db.scalars(query)], "kinds": KIND_LABELS}


def _incident_or_404(db: Session, incident_id: int) -> AuthIncident:
    incident = db.get(AuthIncident, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    return incident


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: int, _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    incident = _incident_or_404(db, incident_id)
    ids = (incident.evidence or {}).get("attempt_ids", [])
    query = select(AuthAttempt).order_by(AuthAttempt.id.desc()).limit(100)
    if ids:
        query = query.where(AuthAttempt.id.in_(ids))
    elif incident.source_ip:
        query = query.where(AuthAttempt.source_ip == incident.source_ip)
    return {**incident_out(db, incident, detail=True), "attempts": [attempt_out(db, a) for a in db.scalars(query)]}


@router.get("/attempts")
def attempts(ip: str | None = Query(None, max_length=45), account: str | None = Query(None, max_length=40),
             outcome: str | None = Query(None, pattern="^(success|failure|denied)$"), minutes: int = Query(60, ge=1, le=60 * 24 * 30),
             limit: int = Query(100, ge=1, le=_MAX_PAGE), before_id: int | None = Query(None, gt=0),
             _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    """The real sign-in attempts that reached the backend (newest first). Unknown usernames appear only as keyed hashes."""
    query = select(AuthAttempt).where(AuthAttempt.timestamp >= utcnow() - timedelta(minutes=minutes)).order_by(AuthAttempt.id.desc()).limit(limit)
    if ip:
        query = query.where(AuthAttempt.source_ip == ip)
    if account:
        query = query.where(AuthAttempt.subject == account.upper() if account.upper().startswith(("EMP-", "SEC-")) else AuthAttempt.subject == account)
    if outcome:
        query = query.where(AuthAttempt.outcome == outcome)
    if before_id:
        query = query.where(AuthAttempt.id < before_id)
    return {"rows": [attempt_out(db, a) for a in db.scalars(query)]}


@router.get("/actions")
def actions(status_filter: str | None = Query(None, alias="status", pattern="^(completed|failed|skipped|pending_approval)$"),
            limit: int = Query(100, ge=1, le=_MAX_PAGE), _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    query = select(ResponseAction).order_by(ResponseAction.id.desc()).limit(limit)
    if status_filter:
        query = query.where(ResponseAction.status == status_filter)
    return {"rows": [action_out(db, a) for a in db.scalars(query)], "scope": SCOPE_NOTICE}


# ------------------------------------------------------------------------------------------------------ manual response
class IncidentStatusUpdate(BaseModel):
    status: Literal["investigating", "contained", "resolved", "false_positive"]
    note: str = Field(default="", max_length=500)


@router.post("/incidents/{incident_id}/status")
def update_status(incident_id: int, body: IncidentStatusUpdate, auth: AuthContext = Depends(admin_limited("auth_incident_status")),
                  db: Session = Depends(get_db)):
    incident = _incident_or_404(db, incident_id)
    if body.status in ("resolved", "false_positive") and len(body.note.strip()) < 5:
        raise HTTPException(422, "A resolution note of at least 5 characters is required")
    previous, incident.status = incident.status, body.status
    if body.status in ("resolved", "false_positive"):
        incident.resolution_note = body.note.strip()[:500]
    write_audit(db, "auth_incident_status_changed", actor_id=auth.employee.id, target_type="auth_incident", target_id=incident.id,
                details={"from": previous, "to": body.status, "note": body.note.strip()[:200]})
    db.commit()
    return incident_out(db, incident, detail=True)


class ManualAction(BaseModel):
    action: Literal["lock_account", "unlock_account", "revoke_sessions", "block_ip", "unblock_ip"]
    reason: str = Field(min_length=5, max_length=300)
    target: str | None = Field(default=None, max_length=64, description="Employee ID or IP address; defaults to the incident's")
    minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 90, description="Limit for a lock or block; empty = until removed")
    confirm: bool = False


DISRUPTIVE = {"lock_account", "revoke_sessions", "block_ip"}


def _employee_by_code(db: Session, code: str) -> Employee:
    employee = db.scalar(select(Employee).where(Employee.employee_code == code.strip().upper()))
    if employee is None:
        raise HTTPException(404, "Employee not found")
    return employee


def _valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise HTTPException(422, "Not a valid IP address") from None


def run_manual(db: Session, auth: AuthContext, request: Request, body: ManualAction, incident: AuthIncident | None) -> dict:
    key = idempotency_key(request)
    if key:
        previous = db.scalar(select(ResponseAction).where(ResponseAction.idempotency_key == f"manual:{key}"))
        if previous is not None:
            return {**action_out(db, previous), "replayed": True}
    if body.action in DISRUPTIVE and not body.confirm:
        raise HTTPException(409, "Confirmation required: this action locks, revokes or blocks. Resend with confirm=true.")
    admin_id = auth.employee.id
    common = dict(reason=body.reason, actor_id=admin_id, incident=incident, idempotency_key=f"manual:{key}" if key else None)
    if body.action in ("lock_account", "unlock_account", "revoke_sessions"):
        target = body.target or (_code(db, incident.employee_id) if incident else None)
        if not target:
            raise HTTPException(422, "target (an employee ID) is required")
        employee = _employee_by_code(db, target)
        if body.action == "lock_account":
            if employee.id == admin_id:
                raise HTTPException(422, "You cannot lock your own account")
            row = auth_response.lock_account(db, employee, automatic=False, minutes=body.minutes, **common)
        elif body.action == "unlock_account":
            row = auth_response.unlock_account(db, employee, **common)
        else:
            revoked = auth_response.revoke_sessions(db, employee_id=employee.id)
            write_audit(db, "sessions_revoked", actor_id=admin_id, target_type="employee", target_id=employee.id,
                        details={"count": revoked, "automatic": False})
            row = auth_response._action(db, action_type="revoke_sessions", status="completed" if revoked else "skipped",
                                        target=employee.employee_code or "", result=f"{revoked} session(s) revoked", automatic=False,
                                        employee=employee, details={"sessions_revoked": revoked}, **common)
    else:
        target = body.target or (incident.source_ip if incident else None)
        if not target:
            raise HTTPException(422, "target (an IP address) is required")
        ip = _valid_ip(target)
        if ip == resolve_ip(request):
            raise HTTPException(422, "You cannot block the address you are using")
        if body.action == "block_ip":
            row = auth_response.block_ip(db, ip, automatic=False, minutes=body.minutes, **common)
        else:
            row = auth_response.unblock_ip(db, ip, **common)
    if incident is not None and row is not None and row.status == "completed" and incident.status == "open" and body.action != "unblock_ip":
        incident.status = "contained"
    db.commit()
    return action_out(db, row)


@router.post("/incidents/{incident_id}/actions", status_code=201)
def respond_to_incident(incident_id: int, body: ManualAction, request: Request,
                        auth: AuthContext = Depends(admin_limited("auth_response")), db: Session = Depends(get_db)):
    """Apply a response to an incident: approve a pending action, or lock / unlock / revoke / block / unblock by hand."""
    try:
        return run_manual(db, auth, request, body, _incident_or_404(db, incident_id))
    except ServiceError:
        db.rollback()
        raise


@router.post("/actions", status_code=201)
def respond_directly(body: ManualAction, request: Request, auth: AuthContext = Depends(admin_limited("auth_response")),
                     db: Session = Depends(get_db)):
    """The same responses without an incident (for example removing a block from the blocked-addresses list)."""
    if not body.target:
        raise HTTPException(422, "target is required")
    return run_manual(db, auth, request, body, None)
