"""Builds and maintains attack investigations: collects and preserves correlated evidence, keeps the case file and the
deterministic explanation up to date as new events arrive."""
import hashlib
import json
from datetime import datetime

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from backend import controls, data_exposure, investigation_explainer, run_context, threat_engine
from backend.baseline import baseline_for
from backend.catalog import RESOURCES, SEVERITY_LABELS, STAGE_LABELS, is_self_service, sensitivity_of
from backend.config import get_settings
from backend.database import utcnow
from backend.detection_engine import linked_employee_ids, window_events
from backend.models import (
    AttackInvestigation,
    Employee,
    EmployeeSession,
    InvestigationEvidence,
    SecurityEvent,
)

ACTIVE_STATUSES = ("open", "contained")
TIMELINE_LIMIT = 100
INCIDENT_RELATIONS = {"flagged", "session", "ip", "related_account"}   # these relations make an event part of the incident


def snapshot_of(e: SecurityEvent) -> dict:
    return {
        "event_id": e.id, "employee_id": e.employee.employee_code, "account": e.employee.username, "session_id": e.session_id,
        "event_type": e.event_type, "resource": e.resource, "outcome": e.outcome, "source_ip": e.source_ip,
        "device_info": e.device_info, "records_accessed": e.records_accessed, "records_downloaded": e.records_downloaded,
        "is_synthetic": e.is_synthetic, "scenario": e.scenario, "details": e.details or {}, "risk_points": e.risk_points,
        "risk_flags": e.risk_flags or [], "timestamp": e.timestamp.isoformat(),
    }


def hash_of(snapshot: dict) -> str:
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def collect_events(db: Session, employee: Employee, threat: threat_engine.ThreatAssessment,
                   as_of: datetime) -> dict[int, tuple[SecurityEvent, list[str]]]:
    """Find the events related to the incident by employee, session, source IP, related account, resource and time.

    Returns {event_id: (event, relations)}. The result is a superset of the correlation evidence.
    """
    corr = threat.correlation
    if corr is None or not corr.evidence:
        return {}
    flagged_ids = {ev.event_id for ev in corr.evidence}
    sessions = {ev.session_id for ev in corr.evidence if ev.session_id is not None}
    ips = set(corr.links["ips"])
    resources = {ev.resource for ev in corr.evidence if ev.resource and not is_self_service(ev.resource)}
    linked = linked_employee_ids(db, employee.id)
    created = [i for i in linked if i != employee.id]
    start = min(ev.timestamp for ev in corr.evidence)

    conditions = [SecurityEvent.id.in_(flagged_ids)]
    if sessions:
        conditions.append(SecurityEvent.session_id.in_(sessions))
    if ips:
        conditions.append(SecurityEvent.source_ip.in_(ips))
    if created:
        conditions.append(SecurityEvent.employee_id.in_(created))
    if resources:
        conditions.append(and_(SecurityEvent.employee_id.in_(linked), SecurityEvent.resource.in_(resources)))
    rows = db.scalars(select(SecurityEvent).where(
        or_(SecurityEvent.id.in_(flagged_ids), and_(SecurityEvent.timestamp >= start, SecurityEvent.timestamp <= as_of, or_(*conditions)))
    ).order_by(SecurityEvent.timestamp, SecurityEvent.id)).all()

    found: dict[int, tuple[SecurityEvent, list[str]]] = {}
    for e in rows:
        relations = []
        if e.id in flagged_ids:
            relations.append("flagged")
        if e.session_id in sessions:
            relations.append("session")
        if e.source_ip in ips:
            relations.append("ip")
        if e.employee_id in created:
            relations.append("related_account")
        if e.resource in resources and e.employee_id in linked:
            relations.append("resource")
        found[e.id] = (e, relations)
    return found


def sync_evidence(db: Session, investigation: AttackInvestigation,
                  found: dict[int, tuple[SecurityEvent, list[str]]]) -> dict[int, InvestigationEvidence]:
    """Append newly related events. Existing snapshots are never rewritten; only the relations metadata can grow."""
    rows = {r.event_id: r for r in db.scalars(select(InvestigationEvidence).where(
        InvestigationEvidence.investigation_id == investigation.id))}
    for event_id, (event, relations) in found.items():
        row = rows.get(event_id)
        if row is None:
            snapshot = snapshot_of(event)
            row = InvestigationEvidence(investigation_id=investigation.id, event_id=event_id, snapshot=snapshot,
                                        content_hash=hash_of(snapshot), relations=relations)
            db.add(row)
            rows[event_id] = row
        else:
            merged = list(dict.fromkeys([*(row.relations or []), *relations]))
            if merged != list(row.relations or []):
                row.relations = merged
    db.flush()
    return rows


def evidence_rows(db: Session, investigation_id: int) -> list[InvestigationEvidence]:
    return list(db.scalars(select(InvestigationEvidence).where(InvestigationEvidence.investigation_id == investigation_id)
                           .order_by(InvestigationEvidence.id)))


def integrity(db: Session, investigation: AttackInvestigation) -> dict:
    """Compare every preserved snapshot with the live event it was taken from."""
    rows = evidence_rows(db, investigation.id)
    modified, missing = [], []
    for row in rows:
        live = db.get(SecurityEvent, row.event_id)
        if live is None:
            missing.append(row.event_id)
        elif hash_of(snapshot_of(live)) != row.content_hash:
            modified.append(row.event_id)
    return {"checked": len(rows), "verified": len(rows) - len(modified) - len(missing), "modified": modified,
            "missing": missing, "intact": not modified and not missing, "algorithm": "sha256"}


def _case_file(db: Session, employee: Employee, events: list[SecurityEvent], relations: dict[int, list[str]],
               exposure: dict) -> dict:
    known = set(employee.known_ips or [])
    incident = [e for e in events if INCIDENT_RELATIONS & set(relations.get(e.id, []))]
    flagged = [e for e in events if "flagged" in relations.get(e.id, [])]

    session_ids = sorted({e.session_id for e in incident if e.session_id is not None})
    sessions = []
    for s in db.scalars(select(EmployeeSession).where(EmployeeSession.id.in_(session_ids or [0])).order_by(EmployeeSession.id)):
        sessions.append({"session_id": s.id, "account": s.employee.employee_code, "source_ip": s.ip_address, "device": s.device_info,
                         "started_at": s.created_at.isoformat(), "revoked_at": s.revoked_at.isoformat() if s.revoked_at else None,
                         "event_count": sum(1 for e in incident if e.session_id == s.id)})

    ip_events: dict[str, list[SecurityEvent]] = {}
    for e in incident:
        if e.source_ip not in known and (any(f["rule"] == "unfamiliar_ip" for f in (e.risk_flags or [])) or "ip" in relations.get(e.id, [])):
            ip_events.setdefault(e.source_ip, []).append(e)
    ips = [{"ip": ip, "event_count": len(evs), "first_seen": evs[0].timestamp.isoformat(), "last_seen": evs[-1].timestamp.isoformat(),
            "blocked": controls.is_ip_blocked(db, ip), "accounts": sorted({e.employee.employee_code for e in evs})}
           for ip, evs in sorted(ip_events.items())]

    accounts = [{"employee_id": a.employee_code, "username": a.username, "status": a.status, "job_role": a.job_role,
                 "created_by": employee.employee_code}
                for a in db.scalars(select(Employee).where(Employee.created_by_id == employee.id).order_by(Employee.id))]

    resource_stats: dict[str, dict] = {}
    for e in events:
        if not e.resource or is_self_service(e.resource) or sensitivity_of(e.resource) < 2:
            continue
        if e.event_type not in ("resource_access", "file_download", "data_export", "external_transfer"):
            continue
        s = resource_stats.setdefault(e.resource, {"resource": e.resource, "name": RESOURCES[e.resource]["name"],
                                                    "sensitivity": sensitivity_of(e.resource), "records_accessed": 0,
                                                    "records_downloaded": 0, "denied_attempts": 0, "event_ids": []})
        s["event_ids"].append(e.id)
        if e.outcome == "denied":
            s["denied_attempts"] += 1
        elif e.event_type != "external_transfer":
            s["records_accessed"] += e.records_accessed
            s["records_downloaded"] += e.records_downloaded

    confirmed = [e for e in events if e.event_type == "external_transfer" and e.outcome == "success"
                 and (e.details or {}).get("transfer_status") == "confirmed"]
    return {
        "employee": {"employee_id": employee.employee_code, "department": employee.department, "job_role": employee.job_role,
                     "status": employee.status},
        "sessions": sessions,
        "suspicious_ips": ips,
        "related_accounts": accounts,
        "event_ids": [e.id for e in events],
        "incident_event_ids": [e.id for e in incident],
        "sensitive_resources": sorted(resource_stats.values(), key=lambda s: (-s["sensitivity"], s["resource"])),
        "data": {
            "sensitive_records_accessed": exposure.get("sensitive_records_accessed", 0),
            "records_exported": exposure.get("records_exported", 0),
            "records_potentially_exposed": exposure.get("records_potentially_exposed", 0),
            "confirmed_external_transfers": len(confirmed),
            "records_confirmed_external": exposure.get("records_confirmed_external", 0),
            "external_transfer_confirmed": exposure.get("external_transfer_confirmed", False),
            "status": exposure.get("status", "none"), "status_label": exposure.get("status_label", ""),
        },
        "first_suspicious_event_id": min(flagged, key=lambda e: (e.timestamp, e.id)).id if flagged else None,
        "latest_suspicious_event_id": max(flagged, key=lambda e: (e.timestamp, e.id)).id if flagged else None,
    }


def build_report(db: Session, employee: Employee, as_of: datetime | None = None,
                 threat: threat_engine.ThreatAssessment | None = None,
                 events: list[SecurityEvent] | None = None, relations: dict[int, list[str]] | None = None,
                 exposure: dict | None = None) -> dict:
    as_of = as_of or utcnow()
    threat = threat or threat_engine.assess(db, employee, as_of)
    if events is None:
        events = window_events(db, employee.id, as_of, get_settings().investigation_window_hours * 60)
    relations = relations or {}
    exposure = exposure or threat.exposure

    timeline = [
        {"event_id": e.id, "timestamp": e.timestamp.isoformat(), "account": e.employee.username, "event_type": e.event_type,
         "resource": e.resource, "outcome": e.outcome, "source_ip": e.source_ip, "session_id": e.session_id,
         "risk_points": e.risk_points, "records_downloaded": e.records_downloaded,
         "stages": sorted({s for f in (e.risk_flags or []) for s in f.get("stages", [])}),
         "rules": [f["rule"] for f in (e.risk_flags or [])], "relations": relations.get(e.id, [])}
        for e in events
        if e.risk_points > 0 or e.event_type in ("login", "login_failed", "external_transfer", "administrative_action")
        or relations.get(e.id)
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
        summary = (f"{employee.employee_code} ({employee.job_role}, {employee.department}): heuristic risk score {threat.risk_score:.1f}/100 "
                   f"(not a probability), risk band {SEVERITY_LABELS[threat.level]}; impact severity {threat.impact['label']}; "
                   f"evidence strength {threat.strength['label']}. Current stage: {threat.stage_label}. Observed stages: {chain}. "
                   f"{exposure['statement']}")
    else:
        summary = (f"No correlated attack evidence for {employee.employee_code}. Heuristic risk score {threat.risk_score:.1f}/100 "
                   f"(risk band {SEVERITY_LABELS[threat.level]}).")
    return {
        "attack_stage": threat.stage,
        "risk_score_exact": threat.risk_score,
        "risk_score": threat.score,
        "impact_severity": threat.impact["level"],
        "evidence_strength": threat.strength["level"],
        "summary": summary,
        "timeline": timeline,
        "indicators": indicators,
        "recommended_actions": threat_engine.recommend_actions(threat),
        "exposure": exposure,
    }


def active_for(db: Session, employee: Employee) -> AttackInvestigation | None:
    """The employee's open investigation. Inside a simulation run only that run's own investigation is considered, so
    a run never appends evidence to an investigation created by another run (or by the manual steps)."""
    query = select(AttackInvestigation).where(AttackInvestigation.employee_id == employee.id,
                                              AttackInvestigation.status.in_(ACTIVE_STATUSES))
    run_id = run_context.current_run_id()
    if run_id is not None:
        query = query.where(AttackInvestigation.simulation_run_id == run_id)
    return db.scalar(query.order_by(AttackInvestigation.id.desc()))


def upsert_investigation(db: Session, employee: Employee, as_of: datetime | None = None, synthetic: bool = False,
                         threat: threat_engine.ThreatAssessment | None = None) -> AttackInvestigation:
    """Create the employee's investigation, or update the active one with the newest evidence."""
    as_of = as_of or utcnow()
    threat = threat or threat_engine.assess(db, employee, as_of)
    investigation = active_for(db, employee)
    if investigation is None:
        investigation = AttackInvestigation(employee_id=employee.id, status="open", is_synthetic=synthetic,
                                            simulation_run_id=run_context.current_run_id())
        db.add(investigation)
        db.flush()

    sync_evidence(db, investigation, collect_events(db, employee, threat, as_of))
    rows = {r.event_id: r for r in evidence_rows(db, investigation.id)}
    live = {e.id: e for e in db.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(list(rows) or [0])))}
    events = sorted(live.values(), key=lambda e: (e.timestamp, e.id))
    relations = {eid: list(row.relations or []) for eid, row in rows.items()}
    incident = [e for e in events if INCIDENT_RELATIONS & set(relations[e.id])]
    exposure = data_exposure.assess(incident, threat.level != "normal") if incident else threat.exposure

    report = build_report(db, employee, as_of, threat, events, relations, exposure)
    case_file = _case_file(db, employee, events, relations, exposure)
    explanation = investigation_explainer.explain(
        employee=employee, events=events, threat=threat, baseline=baseline_for(db, employee, as_of), exposure=exposure,
        actions=report["recommended_actions"], synthetic=investigation.is_synthetic or any(e.is_synthetic for e in events),
        relations=relations)
    for key, value in report.items():
        setattr(investigation, key, value)
    investigation.case_file = case_file
    investigation.explanation = explanation
    investigation.attack_type = explanation["attack_type"]["type"]
    investigation.first_event_id = case_file["first_suspicious_event_id"]
    investigation.latest_event_id = case_file["latest_suspicious_event_id"]
    investigation.updated_at = utcnow()
    db.flush()
    return investigation


def refresh_active(db: Session, employee: Employee, as_of: datetime, threat: threat_engine.ThreatAssessment) -> None:
    """Keep an open investigation current even when a new event does not reach the alert threshold."""
    if active_for(db, employee) is not None:
        upsert_investigation(db, employee, as_of, threat=threat)
