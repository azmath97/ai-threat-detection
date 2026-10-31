"""Containment actions executed by security administrators."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.catalog import sensitivity_of
from backend.database import utcnow
from backend.errors import ServiceError
from backend.event_service import OPEN_ALERT_STATUSES, write_audit
from backend.models import (
    AccessPermission,
    AttackInvestigation,
    ContainmentAction,
    Employee,
    EmployeeSession,
    SecurityAlert,
)

ACTION_TYPES = ("revoke_sessions", "lock_account", "restrict_access", "restore_account")


def _revoke_sessions(db: Session, employee_id: int) -> int:
    now = utcnow()
    sessions = db.scalars(
        select(EmployeeSession).where(
            EmployeeSession.employee_id == employee_id,
            EmployeeSession.revoked_at.is_(None),
            EmployeeSession.expires_at > now,
        )
    ).all()
    for s in sessions:
        s.revoked_at = now
    return len(sessions)


def restore_employee(db: Session, target: Employee) -> dict:
    previous = db.scalars(
        select(ContainmentAction)
        .where(ContainmentAction.employee_id == target.id, ContainmentAction.action_type == "restrict_access")
        .order_by(ContainmentAction.id.desc())
    ).all()
    restored: list[dict] = []
    existing = {p.resource for p in target.permissions}
    for action in previous:
        if action.details.get("restored"):
            continue
        for item in action.details.get("removed_permissions", []):
            if item["resource"] not in existing:
                db.add(AccessPermission(employee_id=target.id, resource=item["resource"], access_level=item["access_level"]))
                existing.add(item["resource"])
                restored.append(item)
        action.details = {**action.details, "restored": True}
    if not restored and target.status == "active":
        raise ServiceError(409, "Nothing to restore: account is active and no access was restricted")
    target.status = "active"
    return {"restored_permissions": restored}


def apply_action(
    db: Session,
    admin: Employee,
    target: Employee,
    action_type: str,
    reason: str,
    investigation_id: int | None = None,
    ip: str | None = None,
) -> ContainmentAction:
    if action_type not in ACTION_TYPES:
        raise ServiceError(422, f"Unknown action_type '{action_type}'")
    if target.id == admin.id:
        raise ServiceError(400, "Administrators cannot apply containment actions to their own account")

    investigation = None
    if investigation_id is not None:
        investigation = db.get(AttackInvestigation, investigation_id)
        if investigation is None:
            raise ServiceError(404, "Investigation not found")
        if investigation.employee_id != target.id:
            raise ServiceError(400, "Investigation does not belong to the target employee")

    details: dict = {}
    if action_type == "revoke_sessions":
        details["sessions_revoked"] = _revoke_sessions(db, target.id)
    elif action_type == "lock_account":
        if target.status == "locked":
            raise ServiceError(409, "Account is already locked")
        target.status = "locked"
        details["sessions_revoked"] = _revoke_sessions(db, target.id)
    elif action_type == "restrict_access":
        sensitive = [p for p in target.permissions if sensitivity_of(p.resource) >= 2]
        if not sensitive:
            raise ServiceError(409, "Employee has no confidential or restricted access to remove")
        details["removed_permissions"] = [{"resource": p.resource, "access_level": p.access_level} for p in sensitive]
        for p in sensitive:
            db.delete(p)
    else:
        details = restore_employee(db, target)

    action = ContainmentAction(
        investigation_id=investigation_id,
        employee_id=target.id,
        action_type=action_type,
        status="completed",
        reason=reason,
        performed_by=admin.id,
        details=details,
    )
    db.add(action)

    if action_type != "restore_account":
        if investigation is not None:
            investigation.status = "contained"
            investigation.updated_at = utcnow()
        for alert in db.scalars(
            select(SecurityAlert).where(
                SecurityAlert.employee_id == target.id, SecurityAlert.status.in_(OPEN_ALERT_STATUSES)
            )
        ):
            alert.status = "contained"
            alert.updated_at = utcnow()

    db.flush()
    write_audit(
        db,
        f"containment_{action_type}",
        actor_id=admin.id,
        target_type="employee",
        target_id=target.id,
        ip=ip,
        details={"action_id": action.id, "reason": reason, "investigation_id": investigation_id},
    )
    db.commit()
    return action
