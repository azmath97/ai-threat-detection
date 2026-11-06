"""Response policy engine and enforcement for authentication attacks.

`record_attempt` is the single entry point used by the sign-in code. It stores the attempt, runs the detectors, opens or updates
an incident (one active incident per kind and subject) and, when AUTH_AUTO_RESPONSE is on, applies the policy:

    account_brute_force / distributed_account_attack   lock the targeted account for a limited time (sessions revoked)
    credential_stuffing / ip_failure_burst (critical)   block the source address in this application for a limited time
    login_after_failures (critical)                     revoke sessions, lock the account, block the source address

Enforcement is real inside this application: a locked account cannot sign in or use any token, and a blocked address is
refused on every request (`get_auth`, `authenticate`). It is NOT a firewall rule and does not stop traffic reaching the host;
nothing here is described as a network block.

Safeguards: security administrators are never locked automatically (an attacker could lock the SOC out); loopback, private
and protected addresses are never blocked (see auth_policy.unblockable_reason); automatic locks and blocks are capped per hour,
beyond which the action waits for an analyst; every action is recorded with its trigger, policy, result and expiry.
"""
import hashlib
import hmac
import logging
import time
from datetime import timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend import auth_detection
from backend.auth_policy import AuthPolicy, get_policy, unblockable_reason
from backend.catalog import SEVERITY_RANK
from backend.config import get_settings
from backend.database import utcnow
from backend.event_service import write_audit
from backend.models import (
    AccessDenial,
    AuthAttempt,
    AuthIncident,
    Employee,
    EmployeeSession,
    ExportRequest,
    IpBlock,
    ResponseAction,
)

log = logging.getLogger("auth_defense")

ACTIVE_INCIDENT = ("open", "investigating", "contained")
_last_purge = 0.0


def _stamp(moment) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def subject_for(identifier: str, employee: Employee | None) -> str:
    """The employee ID for a real account, otherwise a keyed hash: unknown identifiers can be counted but never read back."""
    if employee is not None and employee.employee_code:
        return employee.employee_code
    digest = hmac.new(get_settings().secret_key.encode(), identifier.strip().lower().encode(), hashlib.sha256).hexdigest()
    return f"unknown:{digest[:12]}"


# --------------------------------------------------------------------------------------------------------- recording
def _action(db: Session, *, action_type: str, status: str, target: str, reason: str, result: str, automatic: bool,
            incident: AuthIncident | None = None, employee: Employee | None = None, policy: str | None = None,
            actor_id: int | None = None, details: dict | None = None, expires_at=None,
            idempotency_key: str | None = None) -> ResponseAction:
    row = ResponseAction(
        incident_id=incident.id if incident else None, employee_id=employee.id if employee else None, target=target,
        action_type=action_type, status=status, automatic=automatic, policy=policy, performed_by=actor_id,
        reason=reason[:500], result=result[:300], details=details or {}, expires_at=expires_at, idempotency_key=idempotency_key)
    db.add(row)
    db.flush()
    return row


def _already_recorded(db: Session, incident: AuthIncident | None, action_type: str, target: str, status: str) -> bool:
    if incident is None:
        return False
    return db.scalar(select(ResponseAction.id).where(
        ResponseAction.incident_id == incident.id, ResponseAction.action_type == action_type,
        ResponseAction.target == target, ResponseAction.status == status).limit(1)) is not None


def _auto_count(db: Session, action_type: str) -> int:
    return db.scalar(select(func.count(ResponseAction.id)).where(
        ResponseAction.automatic.is_(True), ResponseAction.action_type == action_type, ResponseAction.status == "completed",
        ResponseAction.created_at >= utcnow() - timedelta(hours=1))) or 0


# ------------------------------------------------------------------------------------------------------ enforcement
def revoke_sessions(db: Session, *, employee_id: int | None = None, ip: str | None = None) -> int:
    """Revoke the live sessions of an account and/or from an address. Revoked sessions can never become valid again."""
    now = utcnow()
    query = update(EmployeeSession).where(EmployeeSession.revoked_at.is_(None), EmployeeSession.expires_at > now)
    if employee_id is not None:
        query = query.where(EmployeeSession.employee_id == employee_id)
    if ip is not None:
        query = query.where(EmployeeSession.ip_address == ip)
    return db.execute(query.values(revoked_at=now)).rowcount or 0


def lock_account(db: Session, employee: Employee, *, reason: str, automatic: bool, policy_name: str | None = None,
                 actor_id: int | None = None, minutes: int | None = None, incident: AuthIncident | None = None,
                 policy: AuthPolicy | None = None, idempotency_key: str | None = None) -> ResponseAction | None:
    """Lock an account and revoke its sessions. Returns the recorded action, or None when an automatic call had nothing to do."""
    policy = policy or get_policy()
    code = employee.employee_code or employee.username
    common = dict(action_type="lock_account", target=code, reason=reason, automatic=automatic, incident=incident, employee=employee,
                  policy=policy_name, actor_id=actor_id, idempotency_key=idempotency_key)
    if employee.status == "locked":
        return None if automatic else _action(db, status="skipped", result="the account was already locked", **common)
    if automatic and employee.role == "security_admin":
        if _already_recorded(db, incident, "lock_account", code, "skipped"):
            return None
        return _action(db, status="skipped", result="security administrators are never locked automatically (it would lock the SOC "
                       "out); review manually", **common)
    if automatic and _auto_count(db, "lock_account") >= policy.max_auto_locks_per_hour > 0:
        if _already_recorded(db, incident, "lock_account", code, "pending_approval"):
            return None
        return _action(db, status="pending_approval", result="automatic lock limit reached this hour; an analyst must approve",
                       **common)
    now = utcnow()
    expires = now + timedelta(minutes=minutes) if minutes else None
    locked_by = f"policy:{policy_name}" if automatic else str(employee_ref(db, actor_id))
    # Compare-and-set: only one of several concurrent callers can move the account from active to locked.
    claimed = db.execute(update(Employee).where(Employee.id == employee.id, Employee.status == "active").values(
        status="locked", lock_reason=reason[:200], locked_at=now, lock_expires_at=expires, locked_by=locked_by)).rowcount
    db.refresh(employee)
    if not claimed:
        return None if automatic else _action(db, status="skipped", result="the account was already locked", **common)
    revoked = revoke_sessions(db, employee_id=employee.id)
    write_audit(db, "account_locked", actor_id=actor_id, target_type="employee", target_id=employee.id,
                details={"reason": reason[:200], "automatic": automatic, "policy": policy_name, "sessions_revoked": revoked,
                         "expires_at": expires.isoformat() if expires else None})
    return _action(db, status="completed", result=f"account locked; {revoked} session(s) revoked"
                   + (f"; unlocks automatically at {_stamp(expires)}" if expires else "; stays locked until an analyst unlocks it"),
                   details={"sessions_revoked": revoked}, expires_at=expires, **common)


def employee_ref(db: Session, employee_id: int | None) -> str:
    if employee_id is None:
        return "system"
    return db.scalar(select(Employee.employee_code).where(Employee.id == employee_id)) or str(employee_id)


def unlock_account(db: Session, employee: Employee, *, reason: str, automatic: bool = False, policy_name: str | None = None,
                   actor_id: int | None = None, incident: AuthIncident | None = None,
                   idempotency_key: str | None = None) -> ResponseAction:
    """Unlock an account. Sessions revoked by the lock stay revoked: the employee must sign in again."""
    code = employee.employee_code or employee.username
    common = dict(action_type="unlock_account", target=code, reason=reason, automatic=automatic, incident=incident,
                  employee=employee, policy=policy_name, actor_id=actor_id, idempotency_key=idempotency_key)
    if employee.status != "locked":
        return _action(db, status="skipped", result="the account was not locked", **common)
    released = db.execute(update(Employee).where(Employee.id == employee.id, Employee.status == "locked").values(
        status="active", lock_reason=None, locked_at=None, lock_expires_at=None, locked_by=None)).rowcount
    db.refresh(employee)
    if not released:                                    # another caller unlocked it first
        return _action(db, status="skipped", result="the account was not locked", **common)
    write_audit(db, "account_unlocked", actor_id=actor_id, target_type="employee", target_id=employee.id,
                details={"reason": reason[:200], "automatic": automatic, "policy": policy_name})
    return _action(db, status="completed", result="account unlocked; previously revoked sessions stay revoked", **common)


def release_expired_lock(db: Session, employee: Employee) -> bool:
    """Unlock an account whose *automatic* lock has run out. Manual locks never expire by themselves."""
    if employee.status != "locked" or employee.lock_expires_at is None or employee.lock_expires_at > utcnow():
        return False
    if not (employee.locked_by or "").startswith("policy:"):
        return False
    unlock_account(db, employee, reason="automatic lock expired", automatic=True, policy_name="lock_expiry")
    db.commit()
    return True


def known_addresses(db: Session) -> set[str]:
    return {ip for ips in db.scalars(select(Employee.known_ips)) for ip in (ips or [])}


def expire_blocks(db: Session) -> int:
    """Close blocks whose time has run out, recording each one."""
    now = utcnow()
    expired = list(db.scalars(select(IpBlock).where(IpBlock.active.is_(True), IpBlock.expires_at.is_not(None), IpBlock.expires_at <= now)))
    for block in expired:
        block.active, block.released_at, block.release_reason = False, now, "expired"
        _action(db, action_type="unblock_ip", status="completed", target=block.ip, reason="block expired",
                result="the application-level block expired", automatic=True, policy="block_expiry",
                incident=db.get(AuthIncident, block.incident_id) if block.incident_id else None)
    if expired:
        db.commit()
    return len(expired)


def block_ip(db: Session, ip: str, *, reason: str, automatic: bool, policy_name: str | None = None, actor_id: int | None = None,
             minutes: int | None = None, incident: AuthIncident | None = None, policy: AuthPolicy | None = None,
             idempotency_key: str | None = None) -> ResponseAction | None:
    """Block an address in this application (sign-ins and API calls are refused until the block expires or is removed)."""
    policy = policy or get_policy()
    common = dict(action_type="block_ip", target=ip, reason=reason, automatic=automatic, incident=incident, policy=policy_name,
                  actor_id=actor_id, idempotency_key=idempotency_key)
    why_not = unblockable_reason(ip, policy, known_addresses(db))
    if why_not:
        if automatic and _already_recorded(db, incident, "block_ip", ip, "skipped"):
            return None
        return _action(db, status="skipped", result=f"not blocked: {why_not}", **common)
    expire_blocks(db)
    if db.scalar(select(IpBlock.id).where(IpBlock.ip == ip, IpBlock.active.is_(True)).limit(1)):
        return None if automatic else _action(db, status="skipped", result="the address was already blocked", **common)
    if automatic and _auto_count(db, "block_ip") >= policy.max_auto_blocks_per_hour > 0:
        if _already_recorded(db, incident, "block_ip", ip, "pending_approval"):
            return None
        return _action(db, status="pending_approval", result="automatic block limit reached this hour; an analyst must approve",
                       **common)
    now = utcnow()
    expires = now + timedelta(minutes=minutes) if minutes else None
    try:
        with db.begin_nested():                         # the partial unique index lets exactly one caller create the active block
            db.add(IpBlock(ip=ip, source="policy" if automatic else "analyst", reason=reason[:500],
                           incident_id=incident.id if incident else None, created_by=actor_id, expires_at=expires))
            db.flush()
    except IntegrityError:
        return None if automatic else _action(db, status="skipped", result="the address was already blocked", **common)
    revoked = revoke_sessions(db, ip=ip)
    write_audit(db, "ip_blocked", actor_id=actor_id, target_type="ip", target_id=ip, ip=None,
                details={"reason": reason[:200], "automatic": automatic, "policy": policy_name, "sessions_revoked": revoked,
                         "enforcement": "application-level", "expires_at": expires.isoformat() if expires else None})
    return _action(db, status="completed", expires_at=expires, details={"sessions_revoked": revoked, "enforcement": "application-level"},
                   result=f"blocked in this application; {revoked} session(s) revoked"
                   + (f"; expires at {_stamp(expires)}" if expires else "; stays blocked until an analyst removes it")
                   + ". This is not a firewall rule.", **common)


def unblock_ip(db: Session, ip: str, *, reason: str, actor_id: int | None, incident: AuthIncident | None = None,
               idempotency_key: str | None = None) -> ResponseAction:
    common = dict(action_type="unblock_ip", target=ip, reason=reason, automatic=False, incident=incident, actor_id=actor_id,
                  idempotency_key=idempotency_key)
    block = db.scalar(select(IpBlock).where(IpBlock.ip == ip, IpBlock.active.is_(True)))
    if block is None:
        return _action(db, status="skipped", result="the address was not blocked", **common)
    block.active, block.released_at, block.released_by, block.release_reason = False, utcnow(), actor_id, reason[:200]
    write_audit(db, "ip_unblocked", actor_id=actor_id, target_type="ip", target_id=ip, details={"reason": reason[:200]})
    return _action(db, status="completed", result="application-level block removed", **common)


# ---------------------------------------------------------------------------------------------------------- incidents
def upsert_incident(db: Session, finding: auth_detection.Finding) -> tuple[AuthIncident, bool]:
    """Open an incident for the finding, or refresh the active one for the same kind and subject. Safe under concurrent attempts."""
    def refresh(incident: AuthIncident) -> None:
        if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[incident.severity]:
            write_audit(db, "auth_incident_escalated", target_type="auth_incident", target_id=incident.id,
                        details={"from": incident.severity, "to": finding.severity})
            incident.severity = finding.severity
        incident.title, incident.explanation, incident.evidence = finding.title, finding.explanation, finding.evidence
        incident.attempts_count = max(incident.attempts_count, finding.attempts)
        incident.last_seen = finding.last_seen or utcnow()

    def current() -> AuthIncident | None:
        return db.scalar(select(AuthIncident).where(AuthIncident.dedup_key == finding.dedup_key,
                                                    AuthIncident.status.in_(ACTIVE_INCIDENT)))

    existing = current()
    if existing:
        refresh(existing)
        return existing, False
    incident = AuthIncident(
        kind=finding.kind, severity=finding.severity, status="open", dedup_key=finding.dedup_key, source_ip=finding.source_ip,
        employee_id=finding.employee.id if finding.employee else None, title=finding.title, explanation=finding.explanation,
        evidence=finding.evidence, attempts_count=finding.attempts, first_seen=finding.first_seen or utcnow(),
        last_seen=finding.last_seen or utcnow())
    try:
        with db.begin_nested():
            db.add(incident)
            db.flush()
    except IntegrityError:
        existing = current()
        if existing is None:
            raise
        refresh(existing)
        return existing, False
    write_audit(db, "auth_incident_opened", target_type="auth_incident", target_id=incident.id,
                details={"kind": finding.kind, "severity": finding.severity, "source_ip": finding.source_ip,
                         "employee_id": finding.employee.employee_code if finding.employee else None})
    return incident, True


# ------------------------------------------------------------------------------------------------------ policy engine
def planned_actions(finding: auth_detection.Finding) -> list[str]:
    """What the policy does for a finding (before safeguards)."""
    critical = finding.severity == "critical"
    return {
        "account_brute_force": ["lock_account"],
        "distributed_account_attack": ["lock_account"],
        "credential_stuffing": ["block_ip"] if critical else [],
        "ip_failure_burst": ["block_ip"] if critical else [],
        "login_after_failures": ["revoke_sessions", "lock_account", "block_ip"] if critical else [],
        # refused requests: an alert first; only a clearly extreme pattern ends the account's sessions and locks it, or blocks the address
        "repeated_forbidden_access": ["revoke_sessions", "lock_account"] if critical else [],
        "idor_probe": ["revoke_sessions", "lock_account"] if critical else [],
        "unauthenticated_flood": ["block_ip"] if critical else [],
        "bulk_export_attempt": ["revoke_sessions", "lock_account"] if critical else [],
    }[finding.kind]


def apply_policy(db: Session, incident: AuthIncident, finding: auth_detection.Finding, policy: AuthPolicy) -> list[ResponseAction]:
    done: list[ResponseAction] = []
    reason = f"{finding.title} (incident #{incident.id})"
    for name in planned_actions(finding):
        action = None
        if name == "revoke_sessions" and finding.employee is not None:
            revoked = revoke_sessions(db, employee_id=finding.employee.id)
            if revoked:
                write_audit(db, "sessions_revoked", target_type="employee", target_id=finding.employee.id,
                            details={"count": revoked, "automatic": True, "policy": finding.kind})
                action = _action(db, action_type="revoke_sessions", status="completed", target=finding.employee.employee_code or "",
                                 reason=reason, result=f"{revoked} session(s) revoked", automatic=True, incident=incident,
                                 employee=finding.employee, policy=finding.kind, details={"sessions_revoked": revoked})
        elif name == "lock_account" and finding.employee is not None:
            action = lock_account(db, finding.employee, reason=reason, automatic=True, policy_name=finding.kind,
                                  minutes=policy.account_lock_minutes, incident=incident, policy=policy)
        elif name == "block_ip" and finding.source_ip:
            action = block_ip(db, finding.source_ip, reason=reason, automatic=True, policy_name=finding.kind,
                              minutes=policy.ip_block_minutes, incident=incident, policy=policy)
        if action is not None:
            done.append(action)
    if any(a.status == "completed" for a in done) and incident.status == "open":
        incident.status = "contained"
    return done


# ------------------------------------------------------------------------------------------------------------ facade
def record_attempt(db: Session, *, ip: str, identifier: str, employee: Employee | None, outcome: str, reason: str,
                   device_info: str | None = None) -> list[AuthIncident]:
    """Store one real sign-in attempt, run the detectors and apply the response policy. Never raises: a fault in the
    defence is logged loudly and must not turn a sign-in into a server error (the credential check has already decided)."""
    policy = get_policy()
    if not policy.enabled:
        return []
    try:
        attempt = AuthAttempt(source_ip=ip[:45], subject=subject_for(identifier, employee), employee_id=employee.id if employee else None,
                              outcome=outcome, reason=reason, device_info=(device_info or None) and device_info[:200], timestamp=utcnow())
        db.add(attempt)
        db.flush()
        incidents = []
        for finding in auth_detection.evaluate(db, attempt, employee, policy):
            incident, _ = upsert_incident(db, finding)
            if policy.auto_response:
                apply_policy(db, incident, finding, policy)
            incidents.append(incident)
        db.commit()
        _maybe_purge(db, policy)
        return incidents
    except Exception:  # noqa: BLE001 - see the docstring
        db.rollback()
        log.exception("authentication defence failed for a sign-in attempt; the attempt was not recorded")
        return []


def record_export_request(db: Session, request, employee: Employee) -> list[AuthIncident]:
    """Run the bulk-export detector for a request that was held or refused. Runs inside the caller's transaction (a savepoint),
    so a fault here never loses the request itself or fails the export response."""
    policy = get_policy()
    if not policy.enabled:
        return []
    try:
        with db.begin_nested():
            incidents = []
            for finding in auth_detection.evaluate_export(db, request, employee, policy):
                incident, _ = upsert_incident(db, finding)
                if policy.auto_response:
                    apply_policy(db, incident, finding, policy)
                incidents.append(incident)
        return incidents
    except Exception:  # noqa: BLE001
        log.exception("authentication defence failed for a bulk-export request")
        return []


def record_denial(db: Session, *, ip: str, employee: Employee | None, method: str, route: str, object_ref: str | None,
                  status_code: int) -> list[AuthIncident]:
    """Store one refused API request, run the detectors and apply the response policy. Never raises (see record_attempt)."""
    policy = get_policy()
    if not policy.enabled:
        return []
    try:
        denial = AccessDenial(source_ip=ip[:45], employee_id=employee.id if employee else None, method=method[:8], route=route[:120],
                              object_ref=(object_ref or None) and object_ref[:64], status_code=status_code, timestamp=utcnow())
        db.add(denial)
        db.flush()
        incidents = []
        for finding in auth_detection.evaluate_denial(db, denial, employee, policy):
            incident, _ = upsert_incident(db, finding)
            if policy.auto_response:
                apply_policy(db, incident, finding, policy)
            incidents.append(incident)
        db.commit()
        _maybe_purge(db, policy)
        return incidents
    except Exception:  # noqa: BLE001 - monitoring must never turn a refusal into a server error
        db.rollback()
        log.exception("authentication defence failed for a refused request; it was not recorded")
        return []


def _maybe_purge(db: Session, policy: AuthPolicy) -> None:
    """Keep the attempt and denial tables bounded: drop rows older than the retention period (at most once an hour)."""
    global _last_purge
    if policy.attempt_retention_days <= 0 or time.monotonic() - _last_purge < 3600:
        return
    _last_purge = time.monotonic()
    try:
        cutoff = utcnow() - timedelta(days=policy.attempt_retention_days)
        db.execute(delete(AuthAttempt).where(AuthAttempt.timestamp < cutoff))
        db.execute(delete(AccessDenial).where(AccessDenial.timestamp < cutoff))
        db.execute(delete(ExportRequest).where(ExportRequest.created_at < cutoff, ExportRequest.status != "pending"))
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        log.exception("could not purge old sign-in attempts and refused requests")
