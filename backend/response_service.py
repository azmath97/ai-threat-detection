"""Containment actions executed by security administrators.

Disruptive actions need explicit confirmation (enforced here, not just in the UI). Every attempt is audited,
including failed ones.
"""
import ipaddress

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.catalog import RESOURCES, is_self_service, sensitivity_of
from backend.database import utcnow
from backend.errors import ServiceError
from backend.event_service import OPEN_ALERT_STATUSES, write_audit
from backend.models import (
    AccessPermission,
    AttackInvestigation,
    ContainmentAction,
    Employee,
    EmployeeSession,
    ResponseControl,
    SecurityAlert,
)

ACTION_TYPES = (
    "revoke_sessions", "lock_account", "restrict_access", "remove_privileges", "block_ip", "isolate_system",
    "restore_account", "unblock_ip", "release_system", "resolve_investigation",
)
NEEDS_CONFIRMATION = {"revoke_sessions", "lock_account", "restrict_access", "remove_privileges", "block_ip", "isolate_system",
                      "resolve_investigation"}
ACCOUNT_CONTAINMENT = {"revoke_sessions", "lock_account", "restrict_access", "remove_privileges"}
ACTION_INFO = {
    "revoke_sessions": ("Revoke active sessions", "Immediately signs the account out everywhere.", "employee"),
    "lock_account": ("Disable account", "Locks the account and revokes its sessions.", "employee"),
    "restrict_access": ("Restrict sensitive access", "Removes confidential and restricted permissions (or only the chosen resource).", "employee"),
    "remove_privileges": ("Remove unauthorised privileges", "Downgrades write access to read; strips all access from accounts created during the incident.", "employee"),
    "block_ip": ("Block IP address", "Rejects logins and requests from the address and revokes its sessions.", "ip"),
    "isolate_system": ("Isolate system", "Denies all access to the system until released.", "system"),
    "restore_account": ("Restore account", "Unlocks the account and restores removed access.", "employee"),
    "unblock_ip": ("Unblock IP address", "Removes the block.", "ip"),
    "release_system": ("Release system", "Ends the isolation.", "system"),
    "resolve_investigation": ("Resolve investigation", "Marks the investigation and its alerts resolved. Preserved evidence is kept.", "investigation"),
}


def _revoke_sessions(db: Session, *, employee_id: int | None = None, ip: str | None = None) -> int:
    now = utcnow()
    query = select(EmployeeSession).where(EmployeeSession.revoked_at.is_(None), EmployeeSession.expires_at > now)
    if employee_id is not None:
        query = query.where(EmployeeSession.employee_id == employee_id)
    if ip is not None:
        query = query.where(EmployeeSession.ip_address == ip)
    sessions = db.scalars(query).all()
    for s in sessions:
        s.revoked_at = now
    return len(sessions)


def restore_employee(db: Session, target: Employee) -> dict:
    """Unlock the account and give back anything removed or downgraded by earlier containment."""
    previous = db.scalars(
        select(ContainmentAction)
        .where(ContainmentAction.employee_id == target.id,
               ContainmentAction.action_type.in_(("restrict_access", "remove_privileges")))
        .order_by(ContainmentAction.id.desc())
    ).all()
    restored: list[dict] = []
    current = {p.resource: p for p in target.permissions}
    for action in previous:
        if action.details.get("restored"):
            continue
        for item in action.details.get("removed_permissions", []):
            if item["resource"] not in current:
                perm = AccessPermission(employee_id=target.id, resource=item["resource"], access_level=item["access_level"])
                db.add(perm)
                current[item["resource"]] = perm
                restored.append(item)
        for item in action.details.get("downgraded", []):
            perm = current.get(item["resource"])
            if perm is not None and perm.access_level == item["to"]:
                perm.access_level = item["from"]
                restored.append({"resource": item["resource"], "access_level": item["from"]})
        action.details = {**action.details, "restored": True}
    if not restored and target.status == "active":
        raise ServiceError(409, "Nothing to restore: account is active and no access was removed")
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
    confirm: bool = False,
    value: str | None = None,
) -> ContainmentAction:
    """`target` is the account the action concerns (or the incident's employee for IP / system actions);
    `value` is the IP address or system for block_ip / unblock_ip / isolate_system / release_system."""
    admin_id, target_id = admin.id, target.id
    try:
        return _apply(db, admin, target, action_type, reason, investigation_id, ip, confirm, value)
    except ServiceError as exc:
        db.rollback()
        write_audit(db, "containment_failed", actor_id=admin_id, target_type="employee", target_id=target_id, ip=ip,
                    details={"action": action_type, "reason": reason, "error": exc.message, "http_status": exc.status_code,
                             "value": value, "confirmed": confirm})
        db.commit()
        raise


def _apply(db, admin, target, action_type, reason, investigation_id, ip, confirm, value) -> ContainmentAction:
    if action_type not in ACTION_TYPES:
        raise ServiceError(422, f"Unknown action_type '{action_type}'")
    if action_type in NEEDS_CONFIRMATION and not confirm:
        raise ServiceError(400, f"Confirmation required: '{ACTION_INFO[action_type][0]}' is disruptive and must be confirmed")
    if action_type in ACCOUNT_CONTAINMENT | {"restore_account"} and target.id == admin.id:
        raise ServiceError(400, "Administrators cannot apply containment actions to their own account")

    investigation = None
    if investigation_id is not None:
        investigation = db.get(AttackInvestigation, investigation_id)
        if investigation is None:
            raise ServiceError(404, "Investigation not found")
        if investigation.employee_id != target.id and target.created_by_id != investigation.employee_id:
            raise ServiceError(400, "Investigation does not belong to the target employee or an account they created")
    synthetic = bool(investigation and investigation.is_synthetic) or target.is_synthetic

    details: dict = {}
    control: ResponseControl | None = None
    if action_type == "revoke_sessions":
        details["sessions_revoked"] = _revoke_sessions(db, employee_id=target.id)
    elif action_type == "lock_account":
        if target.status == "locked":
            raise ServiceError(409, "Account is already locked")
        target.status = "locked"
        details["sessions_revoked"] = _revoke_sessions(db, employee_id=target.id)
    elif action_type == "restrict_access":
        if value:
            resource = value.strip()
            if resource not in RESOURCES or is_self_service(resource) or sensitivity_of(resource) < 2:
                raise ServiceError(422, "A confidential or restricted resource is required")
            sensitive = [p for p in target.permissions if p.resource == resource]
            if not sensitive:
                raise ServiceError(409, f"Employee has no access to {RESOURCES[resource]['name']} to remove")
        else:
            sensitive = [p for p in target.permissions if sensitivity_of(p.resource) >= 2]
            if not sensitive:
                raise ServiceError(409, "Employee has no confidential or restricted access to remove")
        details["removed_permissions"] = [{"resource": p.resource, "access_level": p.access_level} for p in sensitive]
        for p in sensitive:
            db.delete(p)
    elif action_type == "remove_privileges":
        removed, downgraded = [], []
        for p in list(target.permissions):
            if target.created_by_id is not None:     # an account created during an incident keeps nothing
                removed.append({"resource": p.resource, "access_level": p.access_level})
                db.delete(p)
            elif p.access_level == "write":
                downgraded.append({"resource": p.resource, "from": "write", "to": "read"})
                p.access_level = "read"
        if not removed and not downgraded:
            raise ServiceError(409, "No elevated privileges to remove")
        details.update({"removed_permissions": removed, "downgraded": downgraded})
    elif action_type in ("block_ip", "unblock_ip"):
        try:
            address = str(ipaddress.ip_address((value or "").strip()))
        except ValueError:
            raise ServiceError(422, "A valid IPv4 or IPv6 address is required")
        existing = db.scalar(select(ResponseControl).where(ResponseControl.kind == "blocked_ip", ResponseControl.value == address,
                                                           ResponseControl.active.is_(True)))
        if action_type == "block_ip":
            if existing is not None:
                raise ServiceError(409, f"{address} is already blocked")
            control = ResponseControl(kind="blocked_ip", value=address, reason=reason, created_by=admin.id, is_synthetic=synthetic)
            details.update({"ip": address, "sessions_revoked": _revoke_sessions(db, ip=address)})
        else:
            if existing is None:
                raise ServiceError(409, f"{address} is not blocked")
            existing.active, existing.released_at = False, utcnow()
            details["ip"] = address
    elif action_type == "restore_account":
        details = restore_employee(db, target)
    elif action_type == "resolve_investigation":
        if investigation is None:
            raise ServiceError(422, "investigation_id is required to resolve an investigation")
        if investigation.status == "resolved":
            raise ServiceError(409, "Investigation is already resolved")
        now = utcnow()
        alerts = db.scalars(select(SecurityAlert).where(SecurityAlert.investigation_id == investigation.id,
                                                        SecurityAlert.status.in_((*OPEN_ALERT_STATUSES, "contained")))).all()
        for alert in alerts:
            alert.status, alert.updated_at = "resolved", now
        details = {"previous_status": investigation.status, "alerts_resolved": [a.id for a in alerts]}
        investigation.status, investigation.closed_at, investigation.updated_at = "resolved", now, now
    else:  # isolate_system / release_system
        system = (value or "").strip()
        if system not in RESOURCES or is_self_service(system):
            raise ServiceError(422, "Unknown system")
        existing = db.scalar(select(ResponseControl).where(ResponseControl.kind == "isolated_system", ResponseControl.value == system,
                                                           ResponseControl.active.is_(True)))
        if action_type == "isolate_system":
            if existing is not None:
                raise ServiceError(409, f"{RESOURCES[system]['name']} is already isolated")
            control = ResponseControl(kind="isolated_system", value=system, reason=reason, created_by=admin.id, is_synthetic=synthetic)
            details["system"] = system
        else:
            if existing is None:
                raise ServiceError(409, f"{RESOURCES[system]['name']} is not isolated")
            existing.active, existing.released_at = False, utcnow()
            details["system"] = system

    action = ContainmentAction(investigation_id=investigation_id, employee_id=target.id, action_type=action_type,
                               status="completed", reason=reason, performed_by=admin.id, details=details)
    db.add(action)
    db.flush()
    if control is not None:
        control.action_id = action.id
        db.add(control)

    if action_type in ACCOUNT_CONTAINMENT:
        if investigation is not None and investigation.status == "open":
            investigation.status = "contained"
            investigation.updated_at = utcnow()
        for alert in db.scalars(select(SecurityAlert).where(SecurityAlert.employee_id == target.id,
                                                            SecurityAlert.status.in_(OPEN_ALERT_STATUSES))):
            alert.status = "contained"
            alert.updated_at = utcnow()

    write_audit(db, f"containment_{action_type}", actor_id=admin.id, target_type="employee", target_id=target.id, ip=ip,
                details={"action_id": action.id, "reason": reason, "investigation_id": investigation_id,
                         "confirmed": confirm, "value": value})
    db.commit()
    return action
