"""Builds and maintains attack investigation reports from the threat engine's assessment."""
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import threat_engine
from backend.catalog import SEVERITY_LABELS, STAGE_LABELS
from backend.config import get_settings
from backend.database import utcnow
from backend.detection_engine import window_events
from backend.models import AttackInvestigation, Employee

ACTIVE_STATUSES = ("open", "contained")
TIMELINE_LIMIT = 100


def build_report(db: Session, employee: Employee, as_of: datetime | None = None,
                 threat: threat_engine.ThreatAssessment | None = None) -> dict:
    as_of = as_of or utcnow()
    threat = threat or threat_engine.assess(db, employee, as_of)
    events = window_events(db, employee.id, as_of, get_settings().investigation_window_hours * 60)
    stages_by_event = {ev.event_id: ev.stages for ev in threat.correlation.evidence} if threat.correlation else {}

    timeline = [
        {"event_id": e.id, "timestamp": e.timestamp.isoformat(), "account": e.employee.username, "event_type": e.event_type,
         "resource": e.resource, "outcome": e.outcome, "source_ip": e.source_ip, "risk_points": e.risk_points,
         "records_downloaded": e.records_downloaded, "stages": stages_by_event.get(e.id, []),
         "rules": [f["rule"] for f in (e.risk_flags or [])]}
        for e in events
        if e.risk_points > 0 or e.event_type in ("login", "login_failed", "external_transfer", "administrative_action")
    ][-TIMELINE_LIMIT:]

    indicators = [f"{f['description']} ({f['target']}{', x' + str(f['count']) if f['count'] > 1 else ''})" for f in threat.factors]
    if threat.correlation and threat.correlation.links["accounts"][1:]:
        indicators.append("Activity spans accounts: " + ", ".join(threat.correlation.links["accounts"]))
    if threat.correlation and threat.correlation.links["ips"]:
        indicators.append("Unfamiliar source IPs: " + ", ".join(threat.correlation.links["ips"]))
    if threat.ml:
        indicators.append(f"Behavioural anomaly score {threat.ml.score:.2f} ({threat.ml.mode.replace('_', ' ')})")

    if threat.correlation and threat.correlation.stages:
        chain = " -> ".join(STAGE_LABELS[s] for s in threat.correlation.stage_history)
        summary = (f"{employee.full_name} ({employee.job_role}, {employee.department}): attack confidence {threat.score}/100 "
                   f"({SEVERITY_LABELS[threat.level]}). Current stage: {threat.stage_label}. Observed stages: {chain}. "
                   f"{threat.exposure['statement']}")
    else:
        summary = (f"No correlated attack evidence for {employee.full_name}. Attack confidence {threat.score}/100 "
                   f"({SEVERITY_LABELS[threat.level]}).")
    return {
        "attack_stage": threat.stage,
        "confidence": round(threat.confidence / 100, 4),
        "risk_score": threat.score,
        "summary": summary,
        "timeline": timeline,
        "indicators": indicators,
        "recommended_actions": threat_engine.recommend_actions(threat),
        "exposure": threat.exposure,
    }


def upsert_investigation(db: Session, employee: Employee, as_of: datetime | None = None, synthetic: bool = False,
                         threat: threat_engine.ThreatAssessment | None = None) -> AttackInvestigation:
    report = build_report(db, employee, as_of, threat)
    investigation = db.scalar(
        select(AttackInvestigation)
        .where(AttackInvestigation.employee_id == employee.id, AttackInvestigation.status.in_(ACTIVE_STATUSES))
        .order_by(AttackInvestigation.id.desc())
    )
    if investigation is None:
        investigation = AttackInvestigation(employee_id=employee.id, status="open", is_synthetic=synthetic)
        db.add(investigation)
    for key, value in report.items():
        setattr(investigation, key, value)
    investigation.updated_at = utcnow()
    db.flush()
    return investigation
