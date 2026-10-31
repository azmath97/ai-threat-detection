"""Rule-based detection. Each event is evaluated against the configurable rules (rules.py / detection_rules.json)
using the employee's role, permissions, historical baseline and the surrounding session context.

A rule only fires when something is genuinely unusual *for this employee*: an unfamiliar IP, an after-hours login
or access that fails because of a missing privilege level is not treated as an attack by itself.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend import rules
from backend.catalog import RESOURCE_EVENT_TYPES, RESOURCES, is_self_service, sensitivity_of
from backend.config import get_settings
from backend.models import Employee, SecurityEvent
from ml.features import Baseline, is_after_hours


@dataclass
class Detection:
    rule: str
    severity: float                       # 0..1
    stages: list[str]
    description: str
    context: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"rule": self.rule, "severity": round(self.severity, 3), "points": round(self.severity * 100),
                "stages": self.stages, "description": self.description, "context": self.context}


def level_for(score: float) -> str:
    s = get_settings()
    if score >= s.threat_critical_threshold:
        return "critical"
    if score >= s.threat_high_threshold:
        return "high_risk"
    if score >= s.threat_suspicious_threshold:
        return "suspicious"
    return "normal"


def linked_employee_ids(db: Session, employee_id: int) -> list[int]:
    """The employee plus any accounts they created; activity of those accounts counts towards them."""
    return [employee_id, *db.scalars(select(Employee.id).where(Employee.created_by_id == employee_id))]


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


def _count_prior(db: Session, employee_id: int, event_type: str, event: SecurityEvent, minutes: int) -> int:
    return db.scalar(
        select(func.count(SecurityEvent.id)).where(
            SecurityEvent.employee_id == employee_id,
            SecurityEvent.event_type == event_type,
            SecurityEvent.timestamp >= event.timestamp - timedelta(minutes=minutes),
            SecurityEvent.timestamp <= event.timestamp,
            SecurityEvent.id != event.id,
        )
    ) or 0


def _already_flagged(db: Session, employee: Employee, event: SecurityEvent, rule_id: str, *, same_ip: bool = False) -> bool:
    """True if an earlier event in the correlation window already carries this rule (contextual rules fire once)."""
    for other in window_events(db, employee.id, event.timestamp, get_settings().correlation_window_minutes):
        if other.id == event.id or (same_ip and other.source_ip != event.source_ip):
            continue
        if any(flag["rule"] == rule_id for flag in (other.risk_flags or [])):
            return True
    return False


def evaluate_event(db: Session, employee: Employee, event: SecurityEvent, baseline: Baseline) -> list[Detection]:
    et = event.event_type
    if et == "logout":
        return []
    s = get_settings()
    found: list[Detection] = []

    def fire(rule_id: str, scale: float = 1.0, **context) -> None:
        cfg = rules.rule(rule_id)
        if cfg.enabled:
            found.append(Detection(rule_id, min(1.0, cfg.severity * scale), list(cfg.stages), cfg.description, context))

    after_hours = is_after_hours(event.timestamp)
    ip_known = event.source_ip in baseline.known_ips

    if not ip_known and (et in ("login", "login_failed") or not _already_flagged(db, employee, event, "unfamiliar_ip", same_ip=True)):
        fire("unfamiliar_ip", ip=event.source_ip)
    if et == "login" and after_hours and baseline.after_hours_rate < rules.param("after_hours_baseline_rate_max") \
            and not _already_flagged(db, employee, event, "off_hours_login"):
        fire("off_hours_login", baseline_after_hours_rate=round(baseline.after_hours_rate, 3))

    if et == "login_failed":
        fire("failed_login")
        if event.resource == "it-admin-console":
            fire("admin_console_login_failed")
        recent = _count_prior(db, employee.id, "login_failed", event, rules.param("failed_login_burst_minutes")) + 1
        if recent >= rules.param("failed_login_burst_count"):
            fire("failed_login_burst", failures=recent)
    if et == "login":
        prior = _count_prior(db, employee.id, "login_failed", event, rules.param("login_after_failures_minutes"))
        if prior >= rules.param("login_after_failures_count"):
            fire("login_after_failures", failures=prior)
        if baseline.created_by_other and baseline.account_age_hours is not None \
                and baseline.account_age_hours < rules.param("new_account_hours"):
            fire("new_account_login", account_age_hours=round(baseline.account_age_hours, 1))

    if et in RESOURCE_EVENT_TYPES and event.resource in RESOURCES and not is_self_service(event.resource):
        sensitivity = sensitivity_of(event.resource)
        owner = RESOURCES[event.resource]["department"]
        permission = baseline.permissions.get(event.resource)
        if event.outcome == "denied" and (event.details or {}).get("reason") == "system_isolated":
            pass  # isolated by the SOC: not the employee's doing, so not evidence against them
        elif event.outcome == "denied":
            if permission is None and sensitivity >= 3:
                fire("restricted_denied", resource=event.resource)
            elif permission is None and sensitivity >= 2 and owner not in ("All", employee.department):
                fire("unauthorised_department_access", resource=event.resource, owner_department=owner)
            else:  # own department, or a permission that exists but is not high enough
                fire("access_denied", resource=event.resource)
        elif event.outcome == "success" and sensitivity >= 3 and event.resource not in baseline.typical_resources \
                and owner != employee.department and not _already_flagged(db, employee, event, "sensitive_access_novel"):
            fire("sensitive_access_novel", resource=event.resource)

        if sensitivity >= 2:
            recent = set(db.scalars(select(SecurityEvent.resource).where(
                SecurityEvent.employee_id == employee.id, SecurityEvent.event_type.in_(RESOURCE_EVENT_TYPES),
                SecurityEvent.timestamp >= event.timestamp - timedelta(minutes=rules.param("rapid_enumeration_minutes")),
                SecurityEvent.timestamp <= event.timestamp, SecurityEvent.id != event.id)))
            classified = {r for r in recent if sensitivity_of(r) >= 2}
            if event.resource not in classified and len(classified) + 1 >= rules.param("rapid_enumeration_resources"):
                fire("rapid_enumeration", distinct_resources=len(classified) + 1)

    bulk = max(s.bulk_record_threshold, baseline.session_download_max * rules.param("large_export_baseline_multiplier"))
    if et in ("file_download", "data_export") and event.outcome == "success":
        if event.records_downloaded >= bulk:
            fire("large_export", records=event.records_downloaded, baseline_session_max=baseline.session_download_max)
        if et == "data_export":
            fire("data_export")

    if et == "external_transfer":
        records = event.records_downloaded or event.records_accessed
        status = (event.details or {}).get("transfer_status", "attempted")
        if baseline.external_transfer_count == 0 or records >= bulk:
            fire("unusual_outbound_transfer", records=records, transfer_status=status)
        if event.outcome == "success" and status == "confirmed":
            fire("external_transfer_confirmed", records=records)

    if et == "permission_change_attempt":
        fire("permission_change_attempt")
    if et == "administrative_action":
        if event.outcome == "denied":
            fire("permission_change_attempt", action=(event.details or {}).get("action"))
        elif (event.details or {}).get("action") == "create_privileged_account":
            routine = employee.department == "IT" and ip_known and not after_hours   # an IT admin doing their job
            fire("privileged_account_created", rules.param("legitimate_role_scale") if routine else 1.0,
                 routine_for_role=routine)
    return found


def apply_rules(db: Session, employee: Employee, event: SecurityEvent, baseline: Baseline) -> list[Detection]:
    """Evaluate the rules and store the outcome on the event (flags + per-event severity 0-100)."""
    detections = evaluate_event(db, employee, event, baseline)
    event.risk_flags = [d.as_dict() for d in detections]
    event.risk_points = round(max((d.severity for d in detections), default=0.0) * 100)
    db.flush()
    return detections
