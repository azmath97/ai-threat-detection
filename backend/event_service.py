"""The event pipeline: persist -> risk score -> correlate -> alert -> investigation."""
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import correlation_engine, detection_engine, investigation_service
from backend.catalog import ACCESS_LEVEL_RANK, ACTION_REQUIRED_LEVEL, ACTION_TO_EVENT, is_self_service
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
    if is_self_service(resource):
        return action in ("view", "download")
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
    device_info: str | None = None,
    records_accessed: int = 0,
    records_downloaded: int = 0,
    is_synthetic: bool = False,
    scenario: str | None = None,
    occurred_at: datetime | None = None,
    evaluate_alerts: bool = True,
    commit: bool = True,
) -> EventResult:
    synthetic = is_synthetic or bool(session and session.is_synthetic)
    event = SecurityEvent(
        employee_id=employee.id,
        session_id=session.id if session else None,
        event_type=event_type,
        resource=resource,
        outcome=outcome,
        source_ip=source_ip,
        device_info=device_info or (session.device_info if session else None),
        records_accessed=records_accessed,
        records_downloaded=records_downloaded,
        is_synthetic=synthetic,
        scenario=scenario,
        details={**(details or {}), **({"synthetic": True} if synthetic else {})},
        timestamp=occurred_at or utcnow(),
    )
    event.employee = employee
    db.add(event)
    db.flush()

    assessment = detection_engine.assess_event(db, employee, event)
    alert = None
    if evaluate_alerts:
        # Accounts created by another employee are attributed to their creator for alerting.
        parent = db.get(Employee, employee.created_by_id) if employee.created_by_id else None
        if parent is not None:
            summary = detection_engine.current_risk(db, parent.id, event.timestamp)
            assessment = RiskAssessment(
                employee_id=parent.id, event_id=event.id, score=summary.score, level=summary.level,
                factors=event.risk_flags, created_at=event.timestamp,
            )
            db.add(assessment)
            db.flush()
        alert = _maybe_raise_alert(db, parent or employee, event, assessment)

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
    device_info: str | None = None,
    is_synthetic: bool = False,
    scenario: str | None = None,
) -> tuple[EventResult, bool]:
    """Authorise a resource action against the permission table and log the outcome."""
    permitted = has_access(db, employee.id, resource, action)
    result = record_event(
        db,
        employee,
        ACTION_TO_EVENT[action],
        source_ip=source_ip,
        resource=resource,
        outcome="success" if permitted else "denied",
        details={**(details or {}), "action": action, "requested_records": record_count},
        session=session,
        device_info=device_info,
        records_accessed=record_count if permitted else 0,
        records_downloaded=record_count if permitted and action in ("download", "export") else 0,
        is_synthetic=is_synthetic,
        scenario=scenario,
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
    investigation = investigation_service.upsert_investigation(db, employee, event.timestamp, synthetic=event.is_synthetic)

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
        alert = SecurityAlert(employee_id=employee.id, severity=severity, status="open", title=title,
                              description=description, is_synthetic=event.is_synthetic)
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
