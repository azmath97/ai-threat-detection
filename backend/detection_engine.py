"""Explainable rule-based risk scoring.

Every event is scored by a set of rules. An employee's risk score is the sum of the
rule points of their events inside a sliding window (RISK_WINDOW_MINUTES), capped at 100,
so risk rises as suspicious behaviour accumulates and decays when activity returns to normal.
"""
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.catalog import RESOURCE_EVENT_TYPES, sensitivity_of
from backend.config import get_settings, to_local
from backend.database import utcnow
from backend.models import Employee, RiskAssessment, SecurityEvent

RULE_DESCRIPTIONS = {
    "unfamiliar_ip": "Activity from an IP address not previously associated with this employee",
    "off_hours": "Activity outside normal business hours",
    "failed_login": "Failed login attempt",
    "failed_login_burst": "Three or more failed logins within 10 minutes",
    "login_after_failures": "Successful login following repeated failures (possible credential compromise)",
    "access_denied": "Attempt to access a resource without permission",
    "restricted_denied": "Denied attempt against a restricted-classification resource",
    "sensitive_access": "Access to a restricted-classification resource",
    "rapid_enumeration": "Rapid access to many different resources (reconnaissance)",
    "bulk_download": "Bulk data retrieval above the configured threshold",
    "data_export": "Data export operation",
    "external_transfer": "Transfer of data to an external destination",
    "permission_change_attempt": "Attempt to change access permissions (privilege escalation)",
    "privileged_account_created": "New privileged account created",
    "new_account_login": "Login by an account created within the last 24 hours by another user",
}


@dataclass
class Factor:
    rule: str
    points: int
    description: str


@dataclass
class RiskSummary:
    score: int
    level: str
    factors: list[dict]


def level_for(score: int) -> str:
    s = get_settings()
    if score >= s.risk_critical_threshold:
        return "critical"
    if score >= s.risk_high_threshold:
        return "high"
    if score >= s.risk_medium_threshold:
        return "medium"
    return "low"


def _factor(rule: str, points: int) -> Factor:
    return Factor(rule, points, RULE_DESCRIPTIONS[rule])


def _count(db: Session, employee_id: int, event_type: str, since: datetime, event: SecurityEvent) -> int:
    return db.scalar(
        select(func.count(SecurityEvent.id)).where(
            SecurityEvent.employee_id == employee_id,
            SecurityEvent.event_type == event_type,
            SecurityEvent.timestamp >= since,
            SecurityEvent.timestamp <= event.timestamp,
            SecurityEvent.id != event.id,
        )
    ) or 0


def _flagged_recently(db: Session, employee: Employee, event: SecurityEvent, rule: str, *,
                      resource: str | None = None, same_ip: bool = False) -> bool:
    """True if an earlier event inside the risk window already carries this rule (so it is not re-scored)."""
    for other in window_events(db, employee.id, event.timestamp, get_settings().risk_window_minutes):
        if other.id == event.id:
            continue
        if resource is not None and other.resource != resource:
            continue
        if same_ip and other.source_ip != event.source_ip:
            continue
        if any(flag["rule"] == rule for flag in (other.risk_flags or [])):
            return True
    return False


def evaluate_event(db: Session, employee: Employee, event: SecurityEvent) -> list[Factor]:
    s = get_settings()
    et = event.event_type
    if et == "logout":
        return []

    factors: list[Factor] = []
    is_login = et in ("login", "login_failed")

    # Contextual signals describe the situation, so they score once per window rather than once per click.
    if event.source_ip not in (employee.known_ips or []):
        if is_login:
            factors.append(_factor("unfamiliar_ip", 20))
        elif not _flagged_recently(db, employee, event, "unfamiliar_ip", same_ip=True):
            factors.append(_factor("unfamiliar_ip", 8))

    local = to_local(event.timestamp)
    if local.weekday() >= 5 or not (s.business_hours_start <= local.hour < s.business_hours_end):
        if not _flagged_recently(db, employee, event, "off_hours"):
            factors.append(_factor("off_hours", 12 if is_login else 5))

    if et == "login_failed":
        factors.append(_factor("failed_login", 10))
        recent = _count(db, employee.id, "login_failed", event.timestamp - timedelta(minutes=10), event)
        if recent + 1 >= 3:
            factors.append(_factor("failed_login_burst", 20))

    if et == "login":
        prior = _count(db, employee.id, "login_failed", event.timestamp - timedelta(minutes=30), event)
        if prior >= 3:
            factors.append(_factor("login_after_failures", 25))

    sensitivity = sensitivity_of(event.resource)
    if event.outcome == "denied" and et in RESOURCE_EVENT_TYPES:
        factors.append(_factor("access_denied", 15))
        if sensitivity >= 3:
            factors.append(_factor("restricted_denied", 10))

    if et in RESOURCE_EVENT_TYPES:
        if event.outcome == "success" and sensitivity >= 3 and not _flagged_recently(
                db, employee, event, "sensitive_access", resource=event.resource):
            factors.append(_factor("sensitive_access", 8))

        # Self-service pages (profile, payslips, directory...) are ignored: only classified data counts.
        since = event.timestamp - timedelta(minutes=10)
        seen = set(
            db.scalars(
                select(SecurityEvent.resource).where(
                    SecurityEvent.employee_id == employee.id,
                    SecurityEvent.event_type.in_(RESOURCE_EVENT_TYPES),
                    SecurityEvent.timestamp >= since,
                    SecurityEvent.timestamp <= event.timestamp,
                    SecurityEvent.id != event.id,
                )
            )
        )
        classified = {r for r in seen if sensitivity_of(r) >= 2}
        if sensitivity >= 2 and event.resource not in classified and len(classified) + 1 >= 5:
            factors.append(_factor("rapid_enumeration", 20))

    if et in ("file_download", "data_export", "external_transfer") and event.outcome == "success":
        if event.records_downloaded >= s.bulk_record_threshold:
            factors.append(_factor("bulk_download", 30))
    if et == "data_export" and event.outcome == "success":
        factors.append(_factor("data_export", 15))
    if et == "external_transfer":
        factors.append(_factor("external_transfer", 20))
    if et == "permission_change_attempt":
        factors.append(_factor("permission_change_attempt", 30))
    if et == "administrative_action":
        if event.outcome == "denied":
            factors.append(_factor("permission_change_attempt", 30))
        elif (event.details or {}).get("action") == "create_privileged_account":
            factors.append(_factor("privileged_account_created", 35))

    if et == "login" and employee.created_by_id and employee.created_at:
        if event.timestamp - employee.created_at < timedelta(hours=24):
            factors.append(_factor("new_account_login", 15))

    return factors


def linked_employee_ids(db: Session, employee_id: int) -> list[int]:
    """The employee plus any accounts they created; activity of those accounts counts towards them."""
    children = db.scalars(select(Employee.id).where(Employee.created_by_id == employee_id))
    return [employee_id, *children]


def window_events(db: Session, employee_id: int, as_of: datetime, minutes: int) -> list[SecurityEvent]:
    return list(
        db.scalars(
            select(SecurityEvent)
            .where(
                SecurityEvent.employee_id.in_(linked_employee_ids(db, employee_id)),
                SecurityEvent.timestamp >= as_of - timedelta(minutes=minutes),
                SecurityEvent.timestamp <= as_of,
            )
            .order_by(SecurityEvent.timestamp, SecurityEvent.id)
        )
    )


def summarise(events: list[SecurityEvent]) -> RiskSummary:
    merged: dict[str, dict] = {}
    for ev in events:
        for flag in ev.risk_flags or []:
            entry = merged.setdefault(flag["rule"], {**flag, "points": 0, "count": 0})
            entry["points"] += flag["points"]
            entry["count"] += 1
    score = min(100, sum(e.risk_points for e in events))
    factors = sorted(merged.values(), key=lambda f: f["points"], reverse=True)
    return RiskSummary(score=score, level=level_for(score), factors=factors)


def current_risk(db: Session, employee_id: int, as_of: datetime | None = None) -> RiskSummary:
    as_of = as_of or utcnow()
    return summarise(window_events(db, employee_id, as_of, get_settings().risk_window_minutes))


def assess_event(db: Session, employee: Employee, event: SecurityEvent) -> RiskAssessment:
    """Score one event, store the result on it and persist a RiskAssessment row."""
    factors = evaluate_event(db, employee, event)
    event.risk_points = sum(f.points for f in factors)
    event.risk_flags = [asdict(f) for f in factors]
    db.flush()
    summary = current_risk(db, employee.id, event.timestamp)
    assessment = RiskAssessment(
        employee_id=employee.id,
        event_id=event.id,
        score=summary.score,
        level=summary.level,
        factors=event.risk_flags,
        created_at=event.timestamp,
    )
    db.add(assessment)
    db.flush()
    return assessment


def assess_employee(db: Session, employee: Employee) -> tuple[RiskAssessment, RiskSummary]:
    """On-demand re-assessment of an employee from their current activity window."""
    summary = current_risk(db, employee.id)
    assessment = RiskAssessment(
        employee_id=employee.id, event_id=None, score=summary.score, level=summary.level, factors=summary.factors
    )
    db.add(assessment)
    db.commit()
    return assessment, summary


def all_current_scores(db: Session) -> dict[int, int]:
    since = utcnow() - timedelta(minutes=get_settings().risk_window_minutes)
    rows = db.execute(
        select(SecurityEvent.employee_id, func.sum(SecurityEvent.risk_points))
        .where(SecurityEvent.timestamp >= since)
        .group_by(SecurityEvent.employee_id)
    )
    raw = {emp_id: int(total or 0) for emp_id, total in rows}
    scores = dict(raw)
    for child_id, parent_id in db.execute(select(Employee.id, Employee.created_by_id).where(Employee.created_by_id.is_not(None))):
        scores[parent_id] = scores.get(parent_id, 0) + raw.get(child_id, 0)
    return {emp_id: min(100, total) for emp_id, total in scores.items()}
