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
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from backend import auth_response, export_policy
from backend.auth_policy import get_policy
from backend.catalog import RESOURCES, SEVERITY_LEVELS
from backend.config import get_settings, to_local
from backend.database import get_db, utcnow
from backend.errors import ServiceError
from backend.event_service import write_audit
from backend.models import (
    INCIDENT_KINDS,
    AccessDenial,
    AuthAttempt,
    AuthIncident,
    Employee,
    ExportRequest,
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
               "login_after_failures": "Successful sign-in after repeated failures",
               "repeated_forbidden_access": "Repeated refused requests by one account",
               "idor_probe": "Probing other people's records (IDOR)", "unauthenticated_flood": "Flood of unauthenticated requests",
               "bulk_export_attempt": "Repeated bulk-export requests that were held or refused"}
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


def export_request_out(db: Session, r: ExportRequest) -> dict:
    labels = {"pending": "Awaiting approval", "approved": "Approved (not yet used)", "denied": "Denied", "used": "Approved and used",
              "expired": "Expired", "refused": "Refused (limit)"}
    return {"id": r.id, "employee_id": _code(db, r.employee_id), "resource": r.resource, "resource_name": RESOURCES.get(r.resource, {}).get("name", r.resource),
            "action": r.action, "records": r.records, "status": r.status, "status_label": labels[r.status], "reason": r.reason,
            "detail": r.detail, "source_ip": r.source_ip, "created_at": _iso(r.created_at), "expires_at": _iso(r.expires_at),
            "decided_by": _code(db, r.decided_by), "decided_at": _iso(r.decided_at), "decision_note": r.decision_note, "used_at": _iso(r.used_at)}


def denial_out(db: Session, d: AccessDenial) -> dict:
    return {"id": d.id, "timestamp": _iso(d.timestamp), "source_ip": d.source_ip, "account": _code(db, d.employee_id) or "-",
            "method": d.method, "route": d.route, "object": d.object_ref, "status_code": d.status_code,
            "meaning": "no valid session" if d.status_code == 401 else "refused: not permitted"}


# ------------------------------------------------------------------------------------------------------------- reads
@router.get("/overview")
def overview(hours: int = Query(24, ge=1, le=24 * 30), _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    auth_response.expire_blocks(db)
    since = utcnow() - timedelta(hours=hours)
    by_outcome = dict(db.execute(select(AuthAttempt.outcome, func.count(AuthAttempt.id)).where(AuthAttempt.timestamp >= since)
                                 .group_by(AuthAttempt.outcome)).all())
    by_status = dict(db.execute(select(AccessDenial.status_code, func.count(AccessDenial.id)).where(AccessDenial.timestamp >= since)
                                .group_by(AccessDenial.status_code)).all())
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
        "refused_requests": {"unauthenticated_401": by_status.get(401, 0), "forbidden_403": by_status.get(403, 0)},
        "active_incidents": {"total": sum(by_severity.values()), **{s: by_severity.get(s, 0) for s in SEVERITY_LEVELS if s != "normal"}},
        "pending_approval": pending,
        "pending_exports": db.scalar(select(func.count(ExportRequest.id)).where(ExportRequest.status == "pending")) or 0,
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
                   "forbidden_alert": policy.forbidden_alert, "forbidden_critical": policy.forbidden_critical,
                   "export_approval_threshold": policy.export_approval_threshold, "export_hard_limit": policy.export_hard_limit,
                   "export_hourly_limit": policy.export_hourly_limit, "export_owner_multiplier": policy.export_owner_multiplier,
                   "export_approval_minutes": policy.export_approval_minutes, "export_attempt_alert": policy.export_attempt_alert,
                   "export_attempt_critical": policy.export_attempt_critical,
                   "export_attempt_window_minutes": policy.export_attempt_window_minutes,
                   "idor_alert": policy.idor_alert, "idor_critical": policy.idor_critical, "unauth_alert": policy.unauth_alert,
                   "unauth_critical": policy.unauth_critical, "access_window_minutes": policy.access_window_minutes,
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
    ev = incident.evidence or {}
    out = incident_out(db, incident, detail=True)
    if ev.get("export_request_ids"):
        rows = db.scalars(select(ExportRequest).where(ExportRequest.id.in_(ev["export_request_ids"])).order_by(ExportRequest.id.desc()).limit(100))
        return {**out, "attempts": [], "denials": [], "export_requests": [export_request_out(db, r) for r in rows]}
    if ev.get("denial_ids"):
        rows = db.scalars(select(AccessDenial).where(AccessDenial.id.in_(ev["denial_ids"])).order_by(AccessDenial.id.desc()).limit(100))
        return {**out, "attempts": [], "denials": [denial_out(db, d) for d in rows], "export_requests": []}
    ids = ev.get("attempt_ids", [])
    query = select(AuthAttempt).order_by(AuthAttempt.id.desc()).limit(100)
    if ids:
        query = query.where(AuthAttempt.id.in_(ids))
    elif incident.source_ip:
        query = query.where(AuthAttempt.source_ip == incident.source_ip)
    return {**out, "attempts": [attempt_out(db, a) for a in db.scalars(query)], "denials": [], "export_requests": []}


@router.get("/export-requests")
def export_requests(req_status: str = Query("pending", alias="status", pattern="^(pending|all|approved|denied|used|expired|refused)$"),
                    limit: int = Query(100, ge=1, le=_MAX_PAGE), _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    """Bulk downloads and exports held for approval or refused, newest first. Reading closes requests whose time has run out."""
    if export_policy.expire_stale(db):
        db.commit()
    query = select(ExportRequest).order_by(ExportRequest.id.desc()).limit(limit)
    if req_status != "all":
        query = query.where(ExportRequest.status == req_status)
    return {"rows": [export_request_out(db, r) for r in db.scalars(query)],
            "rules": {"approval_threshold": get_policy().export_approval_threshold, "hard_limit": get_policy().export_hard_limit,
                      "hourly_limit": get_policy().export_hourly_limit, "owner_multiplier": get_policy().export_owner_multiplier,
                      "approval_minutes": get_policy().export_approval_minutes}}


class ExportDecision(BaseModel):
    decision: Literal["approve", "deny"]
    note: str = Field(min_length=5, max_length=300)
    valid_minutes: int | None = Field(default=None, ge=1, le=60 * 24, description="How long an approval stays usable")


@router.post("/export-requests/{request_id}/decision")
def decide_export(request_id: int, body: ExportDecision, auth: AuthContext = Depends(admin_limited("export_decision")),
                  db: Session = Depends(get_db)):
    """Approve or deny a pending export request. An approval is single-use, bound to the requester, resource, action and size, and
    expires. You cannot decide your own request. Nothing is released by this call: the requester must repeat the export."""
    export_policy.expire_stale(db)
    row = db.get(ExportRequest, request_id)
    if row is None:
        raise HTTPException(404, "Export request not found")
    if row.employee_id == auth.employee.id:
        raise HTTPException(422, "You cannot decide your own export request")
    now = utcnow()
    approve = body.decision == "approve"
    expires = now + timedelta(minutes=body.valid_minutes or get_policy().export_approval_minutes) if approve else None
    changed = db.execute(update(ExportRequest).where(ExportRequest.id == request_id, ExportRequest.status == "pending").values(
        status="approved" if approve else "denied", decided_by=auth.employee.id, decided_at=now, decision_note=body.note.strip(),
        expires_at=expires)).rowcount
    if not changed:
        db.rollback()
        raise HTTPException(409, f"This request is no longer pending ({row.status})")
    write_audit(db, "export_approved" if approve else "export_denied", actor_id=auth.employee.id, target_type="export_request",
                target_id=request_id, details={"requester": _code(db, row.employee_id), "resource": row.resource, "records": row.records,
                                               "note": body.note.strip()[:200], "valid_until": expires.isoformat() if expires else None})
    db.commit()
    db.refresh(row)
    return export_request_out(db, row)


@router.get("/denials")
def denials(ip: str | None = Query(None, max_length=45), account: str | None = Query(None, max_length=16),
            status_filter: int | None = Query(None, alias="status", ge=401, le=403), minutes: int = Query(60, ge=1, le=60 * 24 * 30),
            limit: int = Query(100, ge=1, le=_MAX_PAGE), before_id: int | None = Query(None, gt=0),
            _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    """Real API requests the backend refused with 401 or 403 (newest first). Route templates and ids only; never tokens or bodies."""
    query = select(AccessDenial).where(AccessDenial.timestamp >= utcnow() - timedelta(minutes=minutes)).order_by(AccessDenial.id.desc()).limit(limit)
    if ip:
        query = query.where(AccessDenial.source_ip == ip)
    if account:
        emp_id = db.scalar(select(Employee.id).where(Employee.employee_code == account.upper()))
        query = query.where(AccessDenial.employee_id == (emp_id or -1))
    if status_filter in (401, 403):
        query = query.where(AccessDenial.status_code == status_filter)
    if before_id:
        query = query.where(AccessDenial.id < before_id)
    return {"rows": [denial_out(db, d) for d in db.scalars(query)]}


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
