"""Simulated containment actions executed by security administrators.

Nothing here contacts a firewall, identity provider, endpoint agent, mail server or network: every action edits this
application's own database records (account status, session rows, permission rows, a block list, isolation flags,
investigation and alert status), and this backend's own login and permission code then honours those records.
Each action is recorded with the alert and/or investigation it concerns, the requested action, who initiated it, when, the
outcome and the list of records it changed, and it is audited.

Disruptive actions need explicit confirmation (enforced here, not just in the UI). Every attempt is audited, including
failed ones. A request carrying an `idempotency_key` is replayed, not repeated, when it is retried; a request that would
change nothing is refused with 409 instead of creating a duplicate action.
"""
import ipaddress

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
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

SCOPE_KEY = "simulated_application_state"
SCOPE_NOTICE = ("Containment here is a controlled application simulation. Actions change this application's own records "
                "(accounts, sessions, permissions, blocked addresses, isolated systems) and are enforced by this backend only. "
                "No firewall, directory service, endpoint agent, email service or real network is contacted or changed, and "
                "nothing protects a real organisation.")
RESULT_PREFIX = "Simulation completed: "

ACTION_TYPES = (
    "revoke_sessions", "lock_account", "restrict_access", "remove_privileges", "block_ip", "isolate_system",
    "restore_account", "unblock_ip", "release_system", "resolve_investigation",
)
NEEDS_CONFIRMATION = {"revoke_sessions", "lock_account", "restrict_access", "remove_privileges", "block_ip", "isolate_system",
                      "resolve_investigation"}
ACCOUNT_CONTAINMENT = {"revoke_sessions", "lock_account", "restrict_access", "remove_privileges"}
ACTION_INFO = {
    "revoke_sessions": ("Revoke sessions (simulated)", "Marks the account's session records in this application as revoked, so the backend rejects them.", "employee"),
    "lock_account": ("Disable account (simulated)", "Sets the account record to locked in this application and revokes its session records; this backend then refuses the login.", "employee"),
    "restrict_access": ("Restrict sensitive access (simulated)", "Deletes confidential and restricted permission rows (or only the chosen resource) from this application's access table.", "employee"),
    "remove_privileges": ("Remove privileges (simulated)", "Downgrades write permission rows to read; deletes all permission rows of accounts created during the incident.", "employee"),
    "block_ip": ("Block IP in this application (simulated)", "Adds the address to this application's block list; its login code rejects the address and its session records are revoked. No firewall is involved.", "ip"),
    "isolate_system": ("Isolate system record (simulated)", "Flags the resource as isolated in this application, so its permission check denies everyone until released.", "system"),
    "restore_account": ("Restore account (simulated)", "Sets the account record back to active and restores permission rows removed by earlier simulated containment.", "employee"),
    "unblock_ip": ("Unblock IP (simulated)", "Removes the address from this application's block list.", "ip"),
    "release_system": ("Release system (simulated)", "Clears the isolation flag on the resource record.", "system"),
    "resolve_investigation": ("Resolve investigation", "Marks the investigation and its alerts resolved in this application. Preserved evidence is kept.", "investigation"),
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


def _replay(db: Session, admin_id: int, target_id: int, action_type: str, request: dict, key: str, ip: str | None):
    """The original action for this idempotency key (marked `replayed`), or None if the key is unused."""
    existing = db.scalar(select(ContainmentAction).where(ContainmentAction.idempotency_key == key))
    if existing is None:
        return None
    if (existing.details or {}).get("request") != request or existing.performed_by != admin_id:
        raise ServiceError(409, "This idempotency key was already used for a different containment request")
    write_audit(db, "containment_replayed", actor_id=admin_id, target_type="employee", target_id=target_id, ip=ip,
                details={"action_id": existing.id, "action": action_type, "idempotency_key": key})
    db.commit()
    existing.replayed = True
    return existing


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
    alert_id: int | None = None,
    idempotency_key: str | None = None,
) -> ContainmentAction:
    """`target` is the account the action concerns (or the incident's employee for IP / system actions);
    `value` is the IP address or system for block_ip / unblock_ip / isolate_system / release_system.

    With an `idempotency_key`, retrying the same request returns the original action (marked `replayed`) instead of
    performing it again; reusing the key for a different request is refused."""
    admin_id, target_id = admin.id, target.id
    request = {"employee_id": target_id, "action_type": action_type, "target": (value or "").strip() or None,
               "investigation_id": investigation_id, "alert_id": alert_id}
    try:
        if idempotency_key:
            replay = _replay(db, admin_id, target_id, action_type, request, idempotency_key, ip)
            if replay is not None:
                return replay
        try:
            return _apply(db, admin, target, action_type, reason, investigation_id, ip, confirm, value, alert_id, idempotency_key, request)
        except IntegrityError:
            # a concurrent request with the same key, or the same block / isolation, committed first
            db.rollback()
            if idempotency_key:
                replay = _replay(db, admin_id, target_id, action_type, request, idempotency_key, ip)
                if replay is not None:
                    return replay
            raise ServiceError(409, "A conflicting request was processed at the same moment; refresh and retry") from None
    except ServiceError as exc:
        db.rollback()
        write_audit(db, "containment_failed", actor_id=admin_id, target_type="employee", target_id=target_id, ip=ip,
                    details={"action": action_type, "reason": reason, "error": exc.message, "http_status": exc.status_code,
                             "value": value, "confirmed": confirm, "investigation_id": investigation_id, "alert_id": alert_id,
                             "scope": SCOPE_KEY})
        db.commit()
        raise


def _apply(db, admin, target, action_type, reason, investigation_id, ip, confirm, value, alert_id, idempotency_key,
           request) -> ContainmentAction:
    if action_type not in ACTION_TYPES:
        raise ServiceError(422, f"Unknown action_type '{action_type}'")
    if action_type in NEEDS_CONFIRMATION and not confirm:
        raise ServiceError(400, f"Confirmation required: '{ACTION_INFO[action_type][0]}' is disruptive and must be confirmed")
    if action_type in ACCOUNT_CONTAINMENT | {"restore_account"} and target.id == admin.id:
        raise ServiceError(400, "Administrators cannot apply containment actions to their own account")

    alert = None
    if alert_id is not None:
        alert = db.get(SecurityAlert, alert_id)
        if alert is None:
            raise ServiceError(404, "Alert not found")
        if alert.employee_id != target.id and target.created_by_id != alert.employee_id:
            raise ServiceError(400, "Alert does not belong to the target employee or an account they created")
        if investigation_id is None:
            investigation_id = alert.investigation_id
        elif alert.investigation_id is not None and alert.investigation_id != investigation_id:
            raise ServiceError(400, "Alert belongs to a different investigation")
    investigation = None
    if investigation_id is not None:
        investigation = db.get(AttackInvestigation, investigation_id)
        if investigation is None:
            raise ServiceError(404, "Investigation not found")
        if investigation.employee_id != target.id and target.created_by_id != investigation.employee_id:
            raise ServiceError(400, "Investigation does not belong to the target employee or an account they created")
        if alert is None:
            alert = db.scalar(select(SecurityAlert).where(SecurityAlert.investigation_id == investigation.id)
                              .order_by(SecurityAlert.id.desc()))
    synthetic = bool(investigation and investigation.is_synthetic) or target.is_synthetic

    code = target.employee_code
    details: dict = {}
    effects: list[str] = []
    control: ResponseControl | None = None
    if action_type == "revoke_sessions":
        revoked = _revoke_sessions(db, employee_id=target.id)
        if not revoked:
            raise ServiceError(409, "No active sessions to revoke")
        details["sessions_revoked"] = revoked
        effects.append(f"{revoked} session record(s) of {code} marked revoked in this application's database")
    elif action_type == "lock_account":
        if target.status == "locked":
            raise ServiceError(409, "Account is already locked")
        target.status = "locked"
        details["sessions_revoked"] = _revoke_sessions(db, employee_id=target.id)
        effects += [f"Account record {code} set to locked in this application's database",
                    f"{details['sessions_revoked']} session record(s) marked revoked"]
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
        effects.append(f"{len(sensitive)} permission row(s) of {code} deleted from this application's access table: "
                       + ", ".join(sorted(p.resource for p in sensitive)))
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
        if removed:
            effects.append(f"{len(removed)} permission row(s) of {code} deleted from this application's access table")
        if downgraded:
            effects.append(f"{len(downgraded)} permission row(s) of {code} changed from write to read")
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
            effects += [f"{address} added to this application's block list (no firewall or network device is changed)",
                        f"{details['sessions_revoked']} session record(s) from that address marked revoked"]
        else:
            if existing is None:
                raise ServiceError(409, f"{address} is not blocked")
            existing.active, existing.released_at = False, utcnow()
            details["ip"] = address
            effects.append(f"{address} removed from this application's block list")
    elif action_type == "restore_account":
        details = restore_employee(db, target)
        effects += [f"Account record {code} set to active in this application's database",
                    f"{len(details['restored_permissions'])} permission row(s) restored"]
    elif action_type == "resolve_investigation":
        if investigation is None:
            raise ServiceError(422, "investigation_id is required to resolve an investigation")
        if investigation.status == "resolved":
            raise ServiceError(409, "Investigation is already resolved")
        now = utcnow()
        alerts = db.scalars(select(SecurityAlert).where(SecurityAlert.investigation_id == investigation.id,
                                                        SecurityAlert.status.in_((*OPEN_ALERT_STATUSES, "contained")))).all()
        for resolved_alert in alerts:
            resolved_alert.status, resolved_alert.updated_at = "resolved", now
        details = {"previous_status": investigation.status, "alerts_resolved": [a.id for a in alerts]}
        investigation.status, investigation.closed_at, investigation.updated_at = "resolved", now, now
        effects.append(f"Investigation {investigation.id} and {len(alerts)} alert record(s) marked resolved in this application's database")
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
            effects.append(f"{RESOURCES[system]['name']} flagged as isolated in this application; its permission check now denies everyone")
        else:
            if existing is None:
                raise ServiceError(409, f"{RESOURCES[system]['name']} is not isolated")
            existing.active, existing.released_at = False, utcnow()
            details["system"] = system
            effects.append(f"Isolation flag on {RESOURCES[system]['name']} cleared in this application")

    action = ContainmentAction(investigation_id=investigation_id, alert_id=alert.id if alert else None, employee_id=target.id,
                               action_type=action_type, status="completed", reason=reason, performed_by=admin.id,
                               idempotency_key=idempotency_key, details={})
    db.add(action)
    db.flush()
    if control is not None:
        control.action_id = action.id
        db.add(control)

    contained_alerts: list[int] = []
    if action_type in ACCOUNT_CONTAINMENT:
        if investigation is not None and investigation.status == "open":
            investigation.status = "contained"
            investigation.updated_at = utcnow()
            effects.append(f"Investigation {investigation.id} status set to contained")
        for open_alert in db.scalars(select(SecurityAlert).where(SecurityAlert.employee_id == target.id,
                                                                 SecurityAlert.status.in_(OPEN_ALERT_STATUSES))):
            open_alert.status = "contained"
            open_alert.updated_at = utcnow()
            contained_alerts.append(open_alert.id)
        if contained_alerts:
            effects.append(f"{len(contained_alerts)} alert record(s) status set to contained")

    action.details = {
        **details, "scope": SCOPE_KEY, "request": request, "effects": effects,
        "result": RESULT_PREFIX + "; ".join(effects) + ".", "alerts_contained": contained_alerts,
        "external_systems_contacted": [], "initiated_from_ip": ip,
    }
    write_audit(db, f"containment_{action_type}", actor_id=admin.id, target_type="employee", target_id=target.id, ip=ip,
                details={"action_id": action.id, "reason": reason, "investigation_id": investigation_id,
                         "alert_id": action.alert_id, "confirmed": confirm, "value": value, "scope": SCOPE_KEY,
                         "result": action.details["result"], "idempotency_key": idempotency_key})
    db.commit()
    return action
