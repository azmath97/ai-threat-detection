"""The event pipeline: persist -> risk score -> correlate -> alert -> investigation."""
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import correlation_engine, detection_engine, investigation_service
from backend.catalog import ACCESS_LEVEL_RANK, ACTION_REQUIRED_LEVEL, ACTION_TO_EVENT
from backend.config import get_settings
from backend.database import utcnow
from backend.models import (
    AccessPermission,
    AuditLog,
    Employee,
    EmployeeSession,
    RiskAssessment,
    SecurityAlert,
    SecurityEvent,
)

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
OPEN_ALERT_STATUSES = ("open", "investigating")


@dataclass
class EventResult:
    event: SecurityEvent
    assessment: RiskAssessment
    alert: SecurityAlert | None


def write_audit(
    db: Session,
    action: str,
    *,
    actor_id: int | None = None,
    target_type: str | None = None,
    target_id: int | str | None = None,
    ip: str | None = None,
    details: dict | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        ip_address=ip,
        details=details or {},
    )
    db.add(entry)
    return entry


def has_access(db: Session, employee_id: int, resource: str, action: str) -> bool:
    permission = db.scalar(
        select(AccessPermission).where(
            AccessPermission.employee_id == employee_id, AccessPermission.resource == resource
        )
    )
    if permission is None:
        return False
    return ACCESS_LEVEL_RANK[permission.access_level] >= ACCESS_LEVEL_RANK[ACTION_REQUIRED_LEVEL[action]]


def record_event(
    db: Session,
    employee: Employee,
    event_type: str,
    *,
    source_ip: str,
    resource: str | None = None,
    outcome: str = "success",
    details: dict | None = None,
    session: EmployeeSession | None = None,
    occurred_at: datetime | None = None,
    evaluate_alerts: bool = True,
    commit: bool = True,
) -> EventResult:
    event = SecurityEvent(
        employee_id=employee.id,
        session_id=session.id if session else None,
        event_type=event_type,
        resource=resource,
        outcome=outcome,
        source_ip=source_ip,
        details=details or {},
        timestamp=occurred_at or utcnow(),
    )
    event.employee = employee
    db.add(event)
    db.flush()

    assessment = detection_engine.assess_event(db, employee, event)
    alert = _maybe_raise_alert(db, employee, event, assessment) if evaluate_alerts else None

    if commit:
        db.commit()
    return EventResult(event=event, assessment=assessment, alert=alert)


def access_resource(
    db: Session,
    employee: Employee,
    resource: str,
    action: str,
    *,
    source_ip: str,
    session: EmployeeSession | None,
    record_count: int = 0,
    details: dict | None = None,
) -> tuple[EventResult, bool]:
    """Authorise a resource action against the permission table and log the outcome."""
    permitted = has_access(db, employee.id, resource, action)
    payload = {**(details or {}), "action": action, "record_count": record_count}
    result = record_event(
        db,
        employee,
        ACTION_TO_EVENT[action],
        source_ip=source_ip,
        resource=resource,
        outcome="success" if permitted else "denied",
        details=payload,
        session=session,
    )
    return result, permitted


def _maybe_raise_alert(
    db: Session, employee: Employee, event: SecurityEvent, assessment: RiskAssessment
) -> SecurityAlert | None:
    corr = correlation_engine.correlate(db, employee.id, event.timestamp)
    chain = corr.is_attack and assessment.score >= get_settings().risk_medium_threshold
    if assessment.level not in ("high", "critical") and not chain:
        return None

    severity = assessment.level if assessment.level in ("high", "critical") else "high"
    investigation = investigation_service.upsert_investigation(db, employee, event.timestamp)

    top = ", ".join(f["rule"] for f in assessment.factors) or "accumulated risk"
    stages = " -> ".join(corr.stage_names) if corr.stages else "none"
    title = (
        f"Possible insider threat attack chain: {employee.full_name}"
        if chain
        else f"{severity.title()} risk activity: {employee.full_name}"
    )
    description = (
        f"Risk score {assessment.score}/100 ({assessment.level}). Attack stages: {stages}. "
        f"Latest event: {event.event_type} on {event.resource or 'n/a'} from {event.source_ip} (triggers: {top})."
    )

    statuses = OPEN_ALERT_STATUSES if employee.status == "active" else (*OPEN_ALERT_STATUSES, "contained")
    alert = db.scalar(
        select(SecurityAlert)
        .where(SecurityAlert.employee_id == employee.id, SecurityAlert.status.in_(statuses))
        .order_by(SecurityAlert.id.desc())
    )
    created = alert is None
    if created:
        alert = SecurityAlert(employee_id=employee.id, severity=severity, status="open", title=title, description=description)
        db.add(alert)
    else:
        if SEVERITY_RANK[severity] > SEVERITY_RANK[alert.severity]:
            alert.severity = severity
        alert.title = title
        alert.description = description
        alert.updated_at = utcnow()
    alert.event_id = event.id
    alert.assessment_id = assessment.id
    alert.risk_score = assessment.score
    alert.investigation_id = investigation.id
    db.flush()
    if created:
        write_audit(db, "alert_created", target_type="alert", target_id=alert.id,
                    details={"employee_id": employee.id, "severity": severity, "risk_score": assessment.score})
    return alert
