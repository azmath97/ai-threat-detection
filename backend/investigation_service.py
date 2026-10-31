"""Builds and maintains attack investigation reports."""
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import detection_engine
from backend.config import get_settings
from backend.correlation_engine import CorrelationResult, correlate_events
from backend.database import utcnow
from backend.detection_engine import window_events
from backend.models import AttackInvestigation, Employee, SecurityEvent

ACTIVE_STATUSES = ("open", "contained")
TIMELINE_LIMIT = 100


def _timeline(events: list[SecurityEvent], corr: CorrelationResult) -> list[dict]:
    items = [
        {
            "event_id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "event_type": e.event_type,
            "resource": e.resource,
            "outcome": e.outcome,
            "source_ip": e.source_ip,
            "risk_points": e.risk_points,
            "stages": corr.stages_for_event(e.id),
        }
        for e in events
        if e.risk_points > 0 or e.event_type in ("login", "login_failed")
    ]
    return items[-TIMELINE_LIMIT:]


def _indicators(employee: Employee, events: list[SecurityEvent]) -> list[str]:
    indicators: list[str] = []
    rules = Counter(f["rule"] for e in events for f in (e.risk_flags or []))
    for rule, count in rules.most_common():
        indicators.append(f"{detection_engine.RULE_DESCRIPTIONS[rule]} (x{count})")
    unfamiliar = sorted({e.source_ip for e in events if e.source_ip not in (employee.known_ips or [])})
    if unfamiliar:
        indicators.append(f"Unfamiliar source IPs: {', '.join(unfamiliar)}")
    touched = sorted({e.resource for e in events if e.resource and e.risk_points > 0})
    if touched:
        indicators.append(f"Resources involved in suspicious activity: {', '.join(touched)}")
    records = sum(
        int((e.details or {}).get("record_count", 0))
        for e in events
        if e.event_type in ("file_download", "data_export") and e.outcome == "success"
    )
    if records:
        indicators.append(f"Total records downloaded or exported: {records}")
    return indicators


def _recommendations(score: int, level: str, corr: CorrelationResult) -> list[dict]:
    stages = set(corr.stage_names)
    actions: list[dict] = []
    if level in ("high", "critical") or corr.is_attack:
        actions.append({"action": "revoke_sessions", "priority": "immediate",
                        "reason": "Terminate any session that may be controlled by an attacker"})
    if stages & {"collection", "exfiltration"} or level == "critical":
        actions.append({"action": "restrict_access", "priority": "immediate",
                        "reason": "Remove access to confidential and restricted data to stop further collection or exfiltration"})
    if level == "critical" or len(stages) >= 3:
        actions.append({"action": "lock_account", "priority": "high",
                        "reason": "Multi-stage attack pattern; lock the account pending identity verification"})
    if not actions:
        actions.append({"action": "monitor", "priority": "low",
                        "reason": "No malicious pattern confirmed; continue monitoring"})
    return actions


def build_report(db: Session, employee: Employee, as_of: datetime | None = None) -> dict:
    as_of = as_of or utcnow()
    events = window_events(db, employee.id, as_of, get_settings().investigation_window_hours * 60)
    corr_window = as_of - timedelta(minutes=get_settings().correlation_window_minutes)
    corr = correlate_events([e for e in events if e.timestamp >= corr_window])
    risk = detection_engine.current_risk(db, employee.id, as_of)

    if corr.stages:
        summary = (
            f"{employee.full_name} ({employee.job_role}, {employee.department}) shows {len(corr.stages)} attack stage(s): "
            f"{' -> '.join(corr.stage_names)}. Current risk score {risk.score}/100 ({risk.level}), "
            f"correlation confidence {int(corr.confidence * 100)}%."
        )
    else:
        summary = (
            f"No correlated attack stages found for {employee.full_name}. "
            f"Current risk score {risk.score}/100 ({risk.level})."
        )
    return {
        "attack_stage": corr.highest_stage,
        "confidence": corr.confidence,
        "risk_score": risk.score,
        "summary": summary,
        "timeline": _timeline(events, corr),
        "indicators": _indicators(employee, events),
        "recommended_actions": _recommendations(risk.score, risk.level, corr),
    }


def upsert_investigation(db: Session, employee: Employee, as_of: datetime | None = None) -> AttackInvestigation:
    report = build_report(db, employee, as_of)
    investigation = db.scalar(
        select(AttackInvestigation)
        .where(AttackInvestigation.employee_id == employee.id, AttackInvestigation.status.in_(ACTIVE_STATUSES))
        .order_by(AttackInvestigation.id.desc())
    )
    if investigation is None:
        investigation = AttackInvestigation(employee_id=employee.id, status="open")
        db.add(investigation)
    for key, value in report.items():
        setattr(investigation, key, value)
    investigation.updated_at = utcnow()
    db.flush()
    return investigation
