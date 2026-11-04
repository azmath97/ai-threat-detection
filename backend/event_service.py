"""The event pipeline: persist -> rules -> ML/correlation/confidence -> alert -> investigation."""
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend import baseline as baseline_service
from backend import controls, detection_engine, investigation_service, run_context, threat_engine
from backend.catalog import ACCESS_LEVEL_RANK, ACTION_REQUIRED_LEVEL, ACTION_TO_EVENT, SEVERITY_LABELS, SEVERITY_RANK, STAGE_LABELS, is_self_service
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

OPEN_ALERT_STATUSES = ("open", "investigating")


@dataclass
class EventResult:
    event: SecurityEvent
    assessment: RiskAssessment | None
    alert: SecurityAlert | None
    threat: "threat_engine.ThreatAssessment | None" = None
    duplicate: bool = False


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
    if controls.is_isolated(db, resource):   # an isolated system denies everyone
        return False
    permission = db.scalar(
        select(AccessPermission).where(
            AccessPermission.employee_id == employee_id, AccessPermission.resource == resource
        )
    )
    if permission is None:
        return False
    return ACCESS_LEVEL_RANK[permission.access_level] >= ACCESS_LEVEL_RANK[ACTION_REQUIRED_LEVEL[action]]


def _duplicate_of(db: Session, employee: Employee, request_id: str) -> "EventResult | None":
    """The event already stored for this (employee, request_id) deduplication key, if any."""
    existing = db.scalar(select(SecurityEvent).where(SecurityEvent.employee_id == employee.id,
                                                     SecurityEvent.request_id == request_id))
    if existing is None:
        return None
    latest = db.scalar(select(RiskAssessment).where(RiskAssessment.event_id == existing.id).order_by(RiskAssessment.id.desc()))
    return EventResult(event=existing, assessment=latest, alert=None, duplicate=True)


def _serialise_ingestion(db: Session, employee: Employee) -> None:
    """Make concurrent ingestion for one employee (and the account that owns it) run one at a time.

    The assessment of an event must see every earlier event, and "is there already an open alert / investigation?" must
    not race. PostgreSQL gets that from a row lock taken in a fixed order (so two workers cannot deadlock). The lock is
    FOR NO KEY UPDATE, not FOR UPDATE: a transaction that already inserted a session or event for the employee holds a
    shared foreign-key lock on the row, and two such transactions asking for FOR UPDATE would wait on each other forever.
    SQLite already has a single writer: the write lock taken by the first INSERT is held to the end of the transaction.
    """
    if db.get_bind().dialect.name == "sqlite":
        return
    ids = sorted({employee.id, *([employee.created_by_id] if employee.created_by_id else [])})
    db.execute(select(Employee.id).where(Employee.id.in_(ids)).order_by(Employee.id).with_for_update(key_share=True))


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
    request_id: str | None = None,
    evaluate_alerts: bool = True,
    commit: bool = True,
) -> EventResult:
    """Store an event and run it through detection, all in one transaction.

    The event, its risk assessment, any alert, the investigation and their audit rows are committed together or not at all.

    Deduplication key: `(employee_id, request_id)`. A repeat of the same key (a client retry, a double click, a Streamlit
    rerun, two concurrent requests) returns the original event with `duplicate=True` and stores and scores nothing new.
    A partial unique index makes this hold even when two requests arrive at the same instant.
    `evaluate_alerts=False` (used for bulk history seeding) stores rule flags but skips ML scoring and alerts.
    """
    if request_id:
        duplicate = _duplicate_of(db, employee, request_id)
        if duplicate is not None:
            return duplicate
    _serialise_ingestion(db, employee)
    if request_id:
        duplicate = _duplicate_of(db, employee, request_id)       # re-check now that we hold the lock
        if duplicate is not None:
            return duplicate

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
        request_id=request_id,
        simulation_run_id=run_context.current_run_id(),
        details={**(details or {}), **({"synthetic": True} if synthetic else {})},
        timestamp=occurred_at or utcnow(),
    )
    event.employee = employee
    db.add(event)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        duplicate = _duplicate_of(db, employee, request_id) if request_id and commit else None
        if duplicate is None:
            raise
        return duplicate                                          # the concurrent request with the same key won the race

    # 1. rules, judged against this employee's own baseline, permissions and session context
    detection_engine.apply_rules(db, employee, event, baseline_service.baseline_for(db, employee, event.timestamp))

    assessment, alert, threat = None, None, None
    if evaluate_alerts:
        # 2. ML anomaly score + correlation + baseline + stage -> bounded attack confidence
        threat, assessment = threat_engine.assess_and_store(db, employee, event)
        target = employee
        # Accounts created by another employee are attributed to their creator for alerting.
        parent = db.get(Employee, employee.created_by_id) if employee.created_by_id else None
        if parent is not None:
            threat, assessment = threat_engine.assess_and_store(db, parent, event)
            target = parent
        # 3. alert + investigation when the configured severity is reached
        alert = _maybe_raise_alert(db, target, event, assessment, threat)

    if commit:
        db.commit()
    return EventResult(event=event, assessment=assessment, alert=alert, threat=threat)


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
    request_id: str | None = None,
) -> tuple[EventResult, bool]:
    """Authorise a resource action against the permission table and log the outcome."""
    permitted = has_access(db, employee.id, resource, action)
    reason = {"reason": "system_isolated"} if not permitted and controls.is_isolated(db, resource) else {}
    result = record_event(
        db,
        employee,
        ACTION_TO_EVENT[action],
        source_ip=source_ip,
        resource=resource,
        outcome="success" if permitted else "denied",
        details={**(details or {}), **reason, "action": action, "requested_records": record_count},
        session=session,
        device_info=device_info,
        records_accessed=record_count if permitted else 0,
        records_downloaded=record_count if permitted and action in ("download", "export") else 0,
        is_synthetic=is_synthetic,
        scenario=scenario,
        request_id=request_id,
    )
    return result, permitted


def _maybe_raise_alert(
    db: Session, employee: Employee, event: SecurityEvent, assessment: RiskAssessment, threat: "threat_engine.ThreatAssessment"
) -> SecurityAlert | None:
    """Raise (or update) the employee's alert once attack confidence reaches ALERT_MIN_SEVERITY (critical by default)."""
    settings = get_settings()
    if SEVERITY_RANK[threat.level] < SEVERITY_RANK[settings.alert_min_severity]:
        investigation_service.refresh_active(db, employee, event.timestamp, threat)
        return None
    corr = threat.correlation
    investigation = investigation_service.upsert_investigation(db, employee, event.timestamp, synthetic=event.is_synthetic,
                                                               threat=threat)
    chain = " -> ".join(STAGE_LABELS[s] for s in corr.stage_history) or "none"
    title = f"{SEVERITY_LABELS[threat.level]}: possible insider threat, {employee.employee_code} ({threat.stage_label})"
    description = (f"Attack confidence {threat.score}/100 ({SEVERITY_LABELS[threat.level]}). Current stage: {threat.stage_label}. "
                   f"Observed: {chain}. {threat.exposure['statement']}")
    actions = threat_engine.recommend_actions(threat)
    evidence = [ev.as_dict() for ev in corr.evidence]

    statuses = OPEN_ALERT_STATUSES if employee.status == "active" else (*OPEN_ALERT_STATUSES, "contained")
    alert = db.scalar(
        select(SecurityAlert)
        .where(SecurityAlert.employee_id == employee.id, SecurityAlert.status.in_(statuses))
        .order_by(SecurityAlert.id.desc())
    )
    created = alert is None
    if created:
        alert = SecurityAlert(employee_id=employee.id, severity=threat.level, status="open",
                              is_synthetic=event.is_synthetic or investigation.is_synthetic,
                              event_id=event.id, detected_at=event.timestamp, title=title, description=description)
        db.add(alert)
    else:
        previous = (alert.severity, alert.stage)
        if SEVERITY_RANK[threat.level] > SEVERITY_RANK[alert.severity]:
            alert.severity = threat.level
        alert.title, alert.description, alert.updated_at = title, description, utcnow()
        if (alert.severity, threat.stage) != previous:
            write_audit(db, "alert_updated", target_type="alert", target_id=alert.id,
                        details={"employee_id": employee.id, "from_stage": previous[1], "to_stage": threat.stage,
                                 "severity": alert.severity, "confidence": threat.confidence, "trigger_event_id": event.id})
    alert.assessment_id = assessment.id
    alert.risk_score = max(alert.risk_score or 0, threat.score)
    alert.attack_confidence = max(alert.attack_confidence or 0.0, threat.confidence)
    alert.stage = threat.stage
    alert.first_event_id = corr.first_event_id
    alert.evidence = evidence
    alert.exposure = threat.exposure
    alert.recommended_actions = actions
    alert.investigation_id = investigation.id
    db.flush()
    if created:
        write_audit(db, "alert_created", target_type="alert", target_id=alert.id,
                    details={"employee_id": employee.id, "severity": threat.level, "confidence": threat.confidence,
                             "stage": threat.stage, "trigger_event_id": event.id})
    return alert
