"""Read models for the SOC dashboard. Everything is computed from the database and the detection engine;
nothing here is hardcoded or cached beyond a short, change-token-validated memo of the (relatively costly) assessments."""
import time
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend import controls, detection_states, investigation_explainer, investigation_service, threat_engine
from backend.catalog import (
    RESOURCE_EVENT_TYPES,
    RESOURCES,
    SENSITIVITY_LABELS,
    SEVERITY_LABELS,
    SEVERITY_LEVELS,
    STAGE_LABELS,
    STAGES,
    is_self_service,
    sensitivity_of,
)
from backend.config import get_settings, to_local
from backend.data_exposure import STATUS_LABELS
from backend.database import utcnow
from backend.detection_engine import level_for, linked_employee_ids
from backend.errors import ServiceError
from backend.models import (
    AttackInvestigation,
    AuditLog,
    ContainmentAction,
    Employee,
    EmployeeSession,
    ResponseControl,
    RiskAssessment,
    SecurityAlert,
    SecurityEvent,
)
from backend.response_service import ACTION_INFO, NEEDS_CONFIRMATION, SCOPE_NOTICE

ACTIVE_INVESTIGATION = ("open", "contained")
ATTACK_TYPE_LABELS = {key: label for key, (label, _rank) in investigation_explainer.ATTACK_TYPES.items()}
ACTIVE_ALERT = ("open", "investigating", "contained")
RANK = {stage: i for i, stage in enumerate(STAGES)}
_MEMO: dict = {"token": None, "at": 0.0, "threats": {}}


def iso(dt: datetime | None) -> dict:
    return {"utc": dt.isoformat() if dt else None, "local": to_local(dt).isoformat() if dt else None}


def stage_of(flags: list[dict] | None) -> str | None:
    stages = [s for f in (flags or []) for s in f.get("stages", []) if s in RANK]
    return max(stages, key=RANK.get) if stages else None


# ---------------------------------------------------------------- change token for polling
def version(db: Session) -> dict:
    def last(col):
        value = db.scalar(select(func.max(col)))
        return value.timestamp() if isinstance(value, datetime) else (value or 0)

    parts = {
        "events": db.scalar(select(func.max(SecurityEvent.id))) or 0,
        "assessments": db.scalar(select(func.max(RiskAssessment.id))) or 0,
        "audit": db.scalar(select(func.max(AuditLog.id))) or 0,
        "alerts": f"{db.scalar(select(func.count(SecurityAlert.id))) or 0}:{last(SecurityAlert.updated_at)}",
        "investigations": f"{db.scalar(select(func.count(AttackInvestigation.id))) or 0}:{last(AttackInvestigation.updated_at)}",
        "controls": f"{db.scalar(select(func.count(ResponseControl.id)).where(ResponseControl.active.is_(True))) or 0}:"
                    f"{db.scalar(select(func.max(ResponseControl.id))) or 0}",
        "employees": f"{db.scalar(select(func.count(Employee.id))) or 0}:"
                     f"{db.scalar(select(func.count(Employee.id)).where(Employee.status == 'locked')) or 0}",
    }
    return {**parts, "token": "|".join(str(v) for v in parts.values())}


def current_threats(db: Session) -> dict[int, threat_engine.ThreatAssessment]:
    """Live assessment of every employee, reused until the data changes (or 20 s pass, as windows slide)."""
    token = version(db)["token"]
    if _MEMO["token"] == token and time.time() - _MEMO["at"] < 20:
        return _MEMO["threats"]
    _MEMO.update(token=token, at=time.time(), threats=threat_engine.assess_all(db))
    return _MEMO["threats"]


def _employees(db: Session) -> dict[int, Employee]:
    return {e.id: e for e in db.scalars(select(Employee).order_by(Employee.id))}


def _latest_investigations(db: Session) -> dict[int, AttackInvestigation]:
    result: dict[int, AttackInvestigation] = {}
    for inv in db.scalars(select(AttackInvestigation).order_by(AttackInvestigation.id)):
        previous = result.get(inv.employee_id)
        if previous is None or inv.status in ACTIVE_INVESTIGATION or previous.status not in ACTIVE_INVESTIGATION:
            result[inv.employee_id] = inv
    return result


def _last_event_at(db: Session, employee_id: int) -> datetime | None:
    return db.scalar(select(func.max(SecurityEvent.timestamp)).where(
        SecurityEvent.employee_id.in_(linked_employee_ids(db, employee_id))))


def _action_counts(db: Session) -> dict[int, int]:
    """Completed containment actions per investigation (the state describes the current incident, not old history)."""
    counts: dict[int, int] = {}
    for (investigation_id,) in db.execute(select(ContainmentAction.investigation_id).where(
            ContainmentAction.status == "completed", ContainmentAction.investigation_id.is_not(None))):
        counts[investigation_id] = counts.get(investigation_id, 0) + 1
    return counts


def states_for(threat: "threat_engine.ThreatAssessment | None", *, synthetic: bool, actions: int) -> list[dict]:
    anomaly = threat.ml.score if threat and threat.ml else 0.0
    return detection_states.derive(
        anomaly_score=anomaly, independent_stages=threat.counted_stages if threat else 0,
        exposure_status=(threat.exposure.get("status", "none") if threat else "none"),
        ground_truth_simulation=synthetic, containment_actions=actions)


# ---------------------------------------------------------------- overview
def threat_rows(db: Session) -> list[dict]:
    threats, employees, invs = current_threats(db), _employees(db), _latest_investigations(db)
    action_counts = _action_counts(db)
    alerts = {a.employee_id: a for a in db.scalars(select(SecurityAlert).where(SecurityAlert.status.in_(ACTIVE_ALERT))
                                                   .order_by(SecurityAlert.id))}
    rows = []
    for emp in employees.values():
        if emp.created_by_id:      # accounts created by someone else are attributed to their creator
            continue
        t, inv, alert = threats[emp.id], invs.get(emp.id), alerts.get(emp.id)
        active = bool(inv and inv.status in ACTIVE_INVESTIGATION)
        if t.level == "normal" and not active:
            continue
        last = _last_event_at(db, emp.id)
        rows.append({
            "employee_pk": emp.id, "employee_id": emp.employee_code, "department": emp.department, "job_role": emp.job_role,
            "confidence": t.confidence, "level": t.level, "level_label": SEVERITY_LABELS[t.level],
            "stage": t.stage, "stage_label": t.stage_label,
            "exposure_status": t.exposure.get("status", "none"),
            "exposure_label": STATUS_LABELS[t.exposure.get("status", "none")],
            "records_exposed": t.exposure.get("records_potentially_exposed", 0),
            "ml_score": round(t.ml.score, 3) if t.ml else 0.0, "independent_stages": t.counted_stages,
            "last_event_at": iso(last),
            "investigation_id": inv.id if inv else None, "investigation_status": inv.status if inv else None,
            "alert_id": alert.id if alert else None, "alert_status": alert.status if alert else None,
            "states": states_for(t, synthetic=bool((inv and inv.is_synthetic) or (alert and alert.is_synthetic)),
                                 actions=action_counts.get(inv.id, 0) if inv else 0),
        })
    return sorted(rows, key=lambda r: r["confidence"], reverse=True)


def overview(db: Session) -> dict:
    s, now = get_settings(), utcnow()
    employees, threats = _employees(db), current_threats(db)
    sensitive_ids = [r for r in RESOURCES if not is_self_service(r) and sensitivity_of(r) >= 2]
    sensitive_filter = (SecurityEvent.outcome == "success", SecurityEvent.event_type.in_(RESOURCE_EVENT_TYPES),
                        SecurityEvent.resource.in_(sensitive_ids))
    transfers = db.scalars(select(SecurityEvent).where(SecurityEvent.event_type == "external_transfer",
                                                       SecurityEvent.outcome == "success")).all()
    day_ago = now - timedelta(hours=24)
    buckets = {(now - timedelta(hours=o)).replace(minute=0, second=0, microsecond=0): 0 for o in range(23, -1, -1)}
    for (ts,) in db.execute(select(SecurityEvent.timestamp).where(SecurityEvent.timestamp >= day_ago)):
        hour = ts.replace(minute=0, second=0, microsecond=0)
        if hour in buckets:
            buckets[hour] += 1
    by_level = {level: 0 for level in SEVERITY_LEVELS}
    for emp in employees.values():
        if not emp.created_by_id:
            by_level[threats[emp.id].level] += 1
    return {
        "generated_at": iso(now),
        "kpis": {
            "total_events": db.scalar(select(func.count(SecurityEvent.id))) or 0,
            "events_24h": db.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.timestamp >= day_ago)) or 0,
            "active_investigations": db.scalar(select(func.count(AttackInvestigation.id)).where(
                AttackInvestigation.status.in_(ACTIVE_INVESTIGATION))) or 0,
            "critical_alerts": db.scalar(select(func.count(SecurityAlert.id)).where(
                SecurityAlert.severity == "critical", SecurityAlert.status.in_(ACTIVE_ALERT))) or 0,
            "high_risk_employees": sum(1 for e in employees.values()
                                       if not e.created_by_id and threats[e.id].level in ("high_risk", "critical")),
            "sensitive_records_accessed": db.scalar(select(func.coalesce(func.sum(SecurityEvent.records_accessed), 0))
                                                    .where(*sensitive_filter)) or 0,
            "sensitive_records_24h": db.scalar(select(func.coalesce(func.sum(SecurityEvent.records_accessed), 0))
                                               .where(*sensitive_filter, SecurityEvent.timestamp >= day_ago)) or 0,
            "confirmed_external_transfers": sum(1 for e in transfers if (e.details or {}).get("transfer_status") == "confirmed"),
        },
        "thresholds": {"suspicious": s.threat_suspicious_threshold, "high_risk": s.threat_high_threshold,
                       "critical": s.threat_critical_threshold},
        "threats": threat_rows(db),
        "events_per_hour": [{"hour": h.isoformat(), "count": c} for h, c in buckets.items()],
        "employees_by_severity": by_level,
    }


def confidence_history(db: Session, employee_id: int, minutes: int) -> list[dict]:
    since = utcnow() - timedelta(minutes=minutes)
    rows = db.execute(select(RiskAssessment.created_at, RiskAssessment.score, RiskAssessment.level, RiskAssessment.stage)
                      .where(RiskAssessment.employee_id == employee_id, RiskAssessment.created_at >= since)
                      .order_by(RiskAssessment.created_at, RiskAssessment.id)).all()
    return [{"time": iso(t), "score": score, "level": level, "stage": stage} for t, score, level, stage in rows]


# ---------------------------------------------------------------- live feed
def event_feed(db: Session, *, employee: str | None, ip: str | None, event_type: str | None, severity: str | None,
               minutes: int | None, limit: int) -> dict:
    latest = (select(RiskAssessment.event_id.label("eid"), func.max(RiskAssessment.id).label("aid"))
              .where(RiskAssessment.event_id.is_not(None)).group_by(RiskAssessment.event_id).subquery())
    query = (select(SecurityEvent, RiskAssessment, Employee)
             .join(Employee, Employee.id == SecurityEvent.employee_id)
             .outerjoin(latest, latest.c.eid == SecurityEvent.id)
             .outerjoin(RiskAssessment, RiskAssessment.id == latest.c.aid))
    if employee:
        query = query.where(Employee.employee_code == employee)
    if ip:
        query = query.where(SecurityEvent.source_ip.like(f"{ip.strip()}%"))
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
    if severity == "normal":
        query = query.where((RiskAssessment.level == "normal") | (RiskAssessment.id.is_(None)))
    elif severity:
        query = query.where(RiskAssessment.level == severity)
    if minutes:
        query = query.where(SecurityEvent.timestamp >= utcnow() - timedelta(minutes=minutes))
    rows = db.execute(query.order_by(SecurityEvent.id.desc()).limit(limit)).all()
    return {
        "latest_id": db.scalar(select(func.max(SecurityEvent.id))) or 0,
        "rows": [{
            "id": e.id, "timestamp": iso(e.timestamp), "employee_id": emp.employee_code, "account": emp.username,
            "event_type": e.event_type, "source_ip": e.source_ip, "resource": e.resource, "outcome": e.outcome,
            "anomaly_score": round(a.ml_score, 3) if a is not None and a.ml_score is not None else None,
            "confidence": a.score if a is not None else None,
            "severity": a.level if a is not None else "normal",
            "risk_contribution": e.risk_points, "stage": stage_of(e.risk_flags),
            "stage_label": STAGE_LABELS[stage_of(e.risk_flags) or "none"],
            "rules": [f["rule"] for f in (e.risk_flags or [])], "records_accessed": e.records_accessed,
            "records_downloaded": e.records_downloaded, "synthetic": e.is_synthetic, "session_id": e.session_id,
        } for e, a, emp in rows],
    }


# ---------------------------------------------------------------- employee risk monitor
def employee_rows(db: Session) -> list[dict]:
    threats, invs, day_ago = current_threats(db), _latest_investigations(db), utcnow() - timedelta(hours=24)
    counts = dict(db.execute(select(SecurityEvent.employee_id, func.count(SecurityEvent.id))
                             .where(SecurityEvent.risk_points > 0, SecurityEvent.timestamp >= day_ago)
                             .group_by(SecurityEvent.employee_id)).all())
    last = dict(db.execute(select(SecurityEvent.employee_id, func.max(SecurityEvent.timestamp))
                           .where(SecurityEvent.risk_points > 0).group_by(SecurityEvent.employee_id)).all())
    rows = []
    for emp in _employees(db).values():
        t, inv = threats[emp.id], invs.get(emp.id)
        rows.append({
            "employee_pk": emp.id, "employee_id": emp.employee_code, "department": emp.department, "job_role": emp.job_role,
            "account_type": "Created during incident" if emp.created_by_id else ("Security" if emp.role == "security_admin" else "Standard"),
            "risk_score": t.score, "level": t.level, "level_label": SEVERITY_LABELS[t.level],
            "anomaly_score": round(t.ml.score, 3) if t.ml else 0.0,
            "suspicious_events_24h": counts.get(emp.id, 0), "last_suspicious": iso(last.get(emp.id)),
            "stage_label": t.stage_label, "status": emp.status,
            "investigation_id": inv.id if inv else None, "investigation_status": inv.status if inv else "none",
        })
    return sorted(rows, key=lambda r: (r["risk_score"], r["suspicious_events_24h"]), reverse=True)


# ---------------------------------------------------------------- investigations
def _timeline_edge(items: list[dict]) -> tuple[dict | None, dict | None]:
    flagged = [i for i in items if i.get("rules")] or items
    brief = lambda i: None if i is None else {"event_id": i["event_id"], "event_type": i["event_type"],
                                              "resource": i["resource"], "timestamp": i["timestamp"], "account": i.get("account")}
    return (brief(flagged[0]) if flagged else None, brief(items[-1]) if items else None)


def _codes_by_username(db: Session) -> dict[str, str]:
    return {e.username: e.employee_code for e in _employees(db).values()}


def _with_local(item: dict | None, codes: dict[str, str] | None = None) -> dict | None:
    if item is None:
        return None
    ts = datetime.fromisoformat(item["timestamp"])
    account = item.get("account")
    extra = {"account": codes.get(account, account)} if codes and account else {}
    return {**item, **extra, "timestamp": {"utc": ts.isoformat(), "local": to_local(ts).isoformat()}}


def investigation_row(inv: AttackInvestigation, alert: SecurityAlert | None) -> dict:
    items = sorted(inv.timeline or [], key=lambda i: (i["timestamp"], i["event_id"]))
    first, latest = _timeline_edge(items)
    exposure = inv.exposure or {"status": "none", "records_potentially_exposed": 0}
    level = level_for(inv.risk_score)
    return {
        "id": inv.id, "employee_pk": inv.employee_id, "employee_id": inv.employee.employee_code,
        "confidence": inv.risk_score, "level": level, "level_label": SEVERITY_LABELS[level],
        "stage": inv.attack_stage, "stage_label": STAGE_LABELS.get(inv.attack_stage, inv.attack_stage),
        "attack_type": inv.attack_type, "attack_type_label": ATTACK_TYPE_LABELS.get(inv.attack_type, "Not established"),
        "first_event": _with_local(first), "latest_event": _with_local(latest),
        "exposure_status": exposure.get("status", "none"), "exposure_label": STATUS_LABELS[exposure.get("status", "none")],
        "records_exposed": exposure.get("records_potentially_exposed", 0),
        "status": inv.status, "alert_id": alert.id if alert else None, "synthetic": inv.is_synthetic,
        "created_at": iso(inv.created_at), "updated_at": iso(inv.updated_at),
    }


def investigation_rows(db: Session, status: str | None = None) -> list[dict]:
    alerts = {a.investigation_id: a for a in db.scalars(select(SecurityAlert).where(SecurityAlert.investigation_id.is_not(None)))}
    query = select(AttackInvestigation).order_by(AttackInvestigation.updated_at.desc())
    if status == "active":
        query = query.where(AttackInvestigation.status.in_(ACTIVE_INVESTIGATION))
    elif status:
        query = query.where(AttackInvestigation.status == status)
    return [investigation_row(inv, alerts.get(inv.id)) for inv in db.scalars(query)]


def _live_case_file(db: Session, case: dict | None) -> dict | None:
    """The stored case file with enforcement state (blocked IPs, revoked sessions, account status) read live."""
    if not case:
        return case
    revoked = {s.id: s.revoked_at for s in db.scalars(select(EmployeeSession).where(
        EmployeeSession.id.in_([s["session_id"] for s in case.get("sessions", [])] or [0])))}
    status = {e.employee_code: e.status for e in _employees(db).values()}
    return {
        **case,
        "employee": {**case["employee"], "status": status.get(case["employee"]["employee_id"], case["employee"]["status"])},
        "sessions": [{**s, "revoked_at": revoked[s["session_id"]].isoformat() if revoked.get(s["session_id"]) else None}
                     for s in case.get("sessions", [])],
        "suspicious_ips": [{**ip, "blocked": controls.is_ip_blocked(db, ip["ip"])} for ip in case.get("suspicious_ips", [])],
        "related_accounts": [{**a, "status": status.get(a["employee_id"], a["status"])} for a in case.get("related_accounts", [])],
    }


def _audit(live: "threat_engine.ThreatAssessment", alert: SecurityAlert | None) -> dict:
    """How the confidence was built: weighted components, reason codes (rule factors) and the evidence with timestamps."""
    evidence = [{"event_id": e.get("event_id"), "rule": e.get("rule"), "rules": e.get("rules"), "stages": e.get("stages"),
                 "severity": e.get("severity"), "timestamp": e.get("timestamp")} for e in (alert.evidence or [])] if alert else []
    components = [{"component": name, **{k: v for k, v in info.items()}} for name, info in live.components.items()
                  if isinstance(info, dict) and "weight" in info]
    return {
        "confidence": live.confidence, "capped_by_stage_count": bool(live.capped), "components": components,
        "reason_codes": live.factors[:10], "independent_stages": live.counted_stages, "evidence": evidence,
        "note": ("The five components are weighted and summed. Evidence is de-duplicated inside the rule component, but one event can "
                 "still inform more than one component (rule, stage, anomaly features and baseline), so the components are not "
                 "statistically independent. The CERT benchmark pipeline (docs/detection-evaluation.md) counts each evidence "
                 "family once by construction; unifying the live engine with it is future work."),
    }


def investigation_detail(db: Session, investigation_id: int) -> dict:
    inv = db.get(AttackInvestigation, investigation_id)
    if inv is None:
        raise ServiceError(404, "Investigation not found")
    alert = db.scalar(select(SecurityAlert).where(SecurityAlert.investigation_id == inv.id).order_by(SecurityAlert.id.desc()))
    live = current_threats(db).get(inv.employee_id)
    codes = {e.id: e.employee_code for e in _employees(db).values()}
    actions = db.scalars(select(ContainmentAction).where(ContainmentAction.investigation_id == inv.id)
                         .order_by(ContainmentAction.id.desc())).all()
    items = sorted(inv.timeline or [], key=lambda i: (i["timestamp"], i["event_id"]))
    by_name = _codes_by_username(db)
    evidence = [_with_local(ev, by_name) for ev in (alert.evidence or [])] if alert else []
    return {
        **investigation_row(inv, alert),
        "states": states_for(live, synthetic=bool(inv.is_synthetic), actions=len(actions)),
        "audit": None if live is None else _audit(live, alert),
        "state_definitions": detection_states.STATE_DEFINITIONS,
        "summary": inv.summary, "indicators": inv.indicators, "exposure": inv.exposure,
        "first_event_id": inv.first_event_id, "latest_event_id": inv.latest_event_id,
        "resolved_at": iso(inv.closed_at) if inv.closed_at else None,
        "case_file": _live_case_file(db, inv.case_file), "explanation": inv.explanation,
        "integrity": investigation_service.integrity(db, inv),
        "recommended_actions": (alert.recommended_actions if alert and alert.recommended_actions else inv.recommended_actions),
        "timeline": [_with_local(i, by_name) for i in items],
        "alert": None if alert is None else {
            "id": alert.id, "severity": alert.severity, "status": alert.status, "title": alert.title,
            "detected_at": iso(alert.detected_at), "trigger_event_id": alert.event_id, "first_event_id": alert.first_event_id,
            "attack_confidence": alert.attack_confidence, "evidence": evidence,
        },
        "live": None if live is None else {
            "confidence": live.confidence, "level": live.level, "stage": live.stage, "stage_label": live.stage_label,
            "components": live.components, "ml": live.ml.as_dict() if live.ml else None,
            "independent_stages": live.counted_stages,
        },
        "containment_actions": [{"id": a.id, "action": a.action_type, "target": codes.get(a.employee_id), "reason": a.reason,
                                 "by": codes.get(a.performed_by), "at": iso(a.created_at), "details": a.details,
                                 "result": a.result, "alert_id": a.alert_id, "status_label": a.status_label,
                                 "simulated": True} for a in actions],
    }


# ---------------------------------------------------------------- timeline / scopes
def scopes(db: Session) -> list[dict]:
    result = [{"kind": "investigation", "id": r["id"], "employee_pk": r["employee_pk"], "label":
               f"Investigation {r['id']} - {r['employee_id']} - {r['level_label']} {r['confidence']} - {r['stage_label']} ({r['status']})",
               "active": r["status"] in ACTIVE_INVESTIGATION} for r in investigation_rows(db)]
    covered = {r["employee_pk"] for r in result}
    for t in threat_rows(db):
        if t["employee_pk"] not in covered:
            result.append({"kind": "employee", "id": t["employee_pk"], "employee_pk": t["employee_pk"], "active": True,
                           "label": f"Live window - {t['employee_id']} - {t['level_label']} {round(t['confidence'])} - {t['stage_label']}"})
    return result


def timeline(db: Session, investigation_id: int | None, employee_id: int | None) -> dict:
    if investigation_id:
        inv = db.get(AttackInvestigation, investigation_id)
        if inv is None:
            raise ServiceError(404, "Investigation not found")
        items = sorted(inv.timeline or [], key=lambda i: (i["timestamp"], i["event_id"]))
        employee, current, confidence, source = inv.employee, inv.attack_stage, inv.risk_score, f"Investigation {inv.id}"
    else:
        employee = db.get(Employee, employee_id or 0)
        if employee is None:
            raise ServiceError(404, "Employee not found")
        t = current_threats(db)[employee.id]
        evidence = t.correlation.evidence if t.correlation else []
        items = [{"event_id": ev.event_id, "timestamp": ev.timestamp.isoformat(), "account": ev.account,
                  "event_type": ev.event_type, "resource": ev.resource, "outcome": ev.outcome, "source_ip": ev.source_ip,
                  "risk_points": round(ev.severity * 100), "stages": ev.stages, "rules": ev.rules} for ev in evidence]
        current, confidence, source = t.stage, t.score, "Live correlation window"
    lanes = []
    by_name = _codes_by_username(db)
    for stage in STAGES:
        evs = [i for i in items if stage in i.get("stages", [])]
        lanes.append({"stage": stage, "label": STAGE_LABELS[stage], "reached": bool(evs), "current": stage == current,
                      "event_count": len(evs), "first_seen": _with_local(evs[0])["timestamp"] if evs else None,
                      "last_seen": _with_local(evs[-1])["timestamp"] if evs else None,
                      "rules": sorted({r for i in evs for r in i.get("rules", [])})})
    return {"source": source, "employee_pk": employee.id, "employee_id": employee.employee_code,
            "current_stage": current, "current_stage_label": STAGE_LABELS.get(current, current), "confidence": confidence,
            "level": level_for(confidence), "stages": lanes, "events": [_with_local(i, by_name) for i in items]}


# ---------------------------------------------------------------- attack graph
def graph(db: Session, investigation_id: int | None, employee_id: int | None, minutes: int | None) -> dict:
    now = utcnow()
    if investigation_id:
        inv = db.get(AttackInvestigation, investigation_id)
        if inv is None:
            raise ServiceError(404, "Investigation not found")
        stamps = [datetime.fromisoformat(i["timestamp"]) for i in (inv.timeline or [])] or [inv.created_at]
        start, end = min(stamps) - timedelta(minutes=10), min(now, max(stamps) + timedelta(minutes=10))
        subject = inv.employee
    else:
        subject = db.get(Employee, employee_id or 0)
        if subject is None:
            raise ServiceError(404, "Employee not found")
        start, end = now - timedelta(minutes=minutes or get_settings().correlation_window_minutes), now
    ids = linked_employee_ids(db, subject.id)
    events = db.scalars(select(SecurityEvent).where(
        SecurityEvent.employee_id.in_(ids), SecurityEvent.timestamp >= start, SecurityEvent.timestamp <= end)
        .order_by(SecurityEvent.id).limit(800)).all()
    people = {e.id: e for e in db.scalars(select(Employee).where(Employee.id.in_(ids)))}

    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}

    def node(key, label, kind, suspicious=False, **meta):
        n = nodes.setdefault(key, {"id": key, "label": label, "kind": kind, "suspicious": False, "meta": meta})
        n["suspicious"] = n["suspicious"] or suspicious

    def edge(src, dst, kind, flagged, outcome="success", records=0, label=""):
        e = edges.setdefault((src, dst, kind, outcome), {"source": src, "target": dst, "kind": kind, "outcome": outcome,
                                                          "count": 0, "records": 0, "suspicious": False, "label": label})
        e["count"] += 1
        e["records"] += records
        e["suspicious"] = e["suspicious"] or flagged

    for ev in events:
        emp = people[ev.employee_id]
        flagged = ev.risk_points > 0
        privileged = emp.created_by_id is not None or "Privileged" in emp.job_role
        acct = f"acct:{emp.id}"
        node(acct, emp.employee_code, "privileged_account" if privileged else "account", flagged, username=emp.username,
             role=emp.job_role)
        if emp.created_by_id in people:
            edge(f"acct:{emp.created_by_id}", acct, "created", True)
        ip = f"ip:{ev.source_ip}"
        unfamiliar = ev.source_ip not in (emp.known_ips or [])
        node(ip, ev.source_ip, "ip", flagged and unfamiliar, unfamiliar=unfamiliar)
        origin = acct
        if ev.session_id:
            origin = f"sess:{ev.session_id}"
            node(origin, f"Session {ev.session_id}", "session", flagged)
            edge(acct, origin, "session", False)
            edge(origin, ip, "origin", flagged and unfamiliar)
        else:
            edge(acct, ip, "attempt", flagged, ev.outcome)
        if ev.resource and not is_self_service(ev.resource):
            system = f"res:{ev.resource}"
            node(system, RESOURCES[ev.resource]["name"], "system", flagged, sensitivity=SENSITIVITY_LABELS[sensitivity_of(ev.resource)])
            if ev.event_type == "external_transfer":
                destination = (ev.details or {}).get("destination") or "external destination"
                node(f"ext:{destination}", destination, "external", True)
                edge(origin, f"ext:{destination}", "transfer", True, "success", ev.records_downloaded)
                edge(system, f"ext:{destination}", "data_flow", True, "success", ev.records_downloaded)
            else:
                edge(origin, system, "access", flagged, ev.outcome, ev.records_accessed)
    for e in edges.values():
        parts = [f"{e['count']} x"] if e["count"] > 1 else []
        if e["kind"] in ("access", "attempt"):
            parts.append(e["outcome"])
        if e["records"]:
            parts.append(f"{e['records']:,} records")
        e["label"] = " ".join(parts)
    return {"subject": subject.employee_code, "from": iso(start), "to": iso(end), "event_count": len(events),
            "nodes": list(nodes.values()), "edges": list(edges.values())}


# ---------------------------------------------------------------- response centre
def _done(db: Session, action: dict, emp: Employee, since: datetime, codes_by_name: dict[str, Employee]) -> bool:
    kind, target = action["action"], action.get("target")
    if kind == "block_ip":
        return controls.is_ip_blocked(db, target)
    if kind == "isolate_system":
        return controls.is_isolated(db, target)
    account = codes_by_name.get(target) if kind == "lock_account" and target else emp
    if kind == "lock_account":
        return bool(account and account.status == "locked")
    if kind in ("revoke_sessions", "restrict_access", "remove_privileges"):
        acts = db.scalars(select(ContainmentAction).where(
            ContainmentAction.employee_id == emp.id, ContainmentAction.created_at >= since,
            ContainmentAction.action_type.in_((kind, "lock_account") if kind == "revoke_sessions" else (kind,)))).all()
        return any(not a.details.get("restored") for a in acts)
    return False


def response_centre(db: Session) -> dict:
    threats, employees = current_threats(db), _employees(db)
    by_username = {e.username: e for e in employees.values()}
    codes = {e.id: e.employee_code for e in employees.values()}
    invs = _latest_investigations(db)
    alerts = {a.employee_id: a for a in db.scalars(select(SecurityAlert).where(SecurityAlert.status.in_(ACTIVE_ALERT))
                                                   .order_by(SecurityAlert.id))}
    items = []
    for row in threat_rows(db):
        emp, t = employees[row["employee_pk"]], threats[row["employee_pk"]]
        alert, inv = alerts.get(emp.id), invs.get(emp.id)
        if alert is None and t.level in ("normal", "suspicious") and not (inv and inv.status in ACTIVE_INVESTIGATION):
            continue
        actions = (alert.recommended_actions if alert and alert.recommended_actions else threat_engine.recommend_actions(t))
        since = alert.created_at if alert else utcnow() - timedelta(days=1)
        items.append({**row, "actions": [{**a, "done": _done(db, a, emp, since, by_username),
                                          "needs_confirmation": a["action"] in NEEDS_CONFIRMATION} for a in actions]})
    active = controls.active_controls(db)
    origin = {a.id: a.employee_id for a in db.scalars(select(ContainmentAction).where(
        ContainmentAction.id.in_([c.action_id for c in active if c.action_id] or [0])))}
    history = db.scalars(select(ContainmentAction).order_by(ContainmentAction.id.desc()).limit(40)).all()
    return {
        "scope_notice": SCOPE_NOTICE,
        "threats": items,
        "controls": [{"id": c.id, "kind": c.kind, "value": c.value, "label": RESOURCES[c.value]["name"] if c.kind == "isolated_system" else c.value,
                      "reason": c.reason, "by": codes.get(c.created_by), "created_at": iso(c.created_at),
                      "employee_pk": origin.get(c.action_id, c.created_by)} for c in active],
        "history": [{"id": a.id, "action": a.action_type, "label": ACTION_INFO[a.action_type][0], "employee_id": codes.get(a.employee_id),
                     "by": codes.get(a.performed_by), "reason": a.reason, "at": iso(a.created_at), "details": a.details,
                     "investigation_id": a.investigation_id, "alert_id": a.alert_id, "result": a.result,
                     "status_label": a.status_label, "simulated": True} for a in history],
        "options": [{"action": k, "label": v[0], "description": v[1], "needs": v[2], "needs_confirmation": k in NEEDS_CONFIRMATION}
                    for k, v in ACTION_INFO.items()],
        "systems": [{"id": rid, "label": meta["name"]} for rid, meta in RESOURCES.items() if not is_self_service(rid)],
        "employees": [{"id": e.id, "employee_id": e.employee_code, "status": e.status} for e in employees.values() if e.role != "security_admin"],
    }


# ---------------------------------------------------------------- audit log
AUDIT_CATEGORIES = {
    "alerts": "Security alerts", "investigations": "Investigation updates", "containment": "Containment actions",
    "administrator": "Administrator actions", "failed_response": "Failed response attempts",
}
_ALERTS = {"alert_created", "alert_updated"}
_INVESTIGATIONS = {"investigation_run", "investigation_status_changed", "alert_status_changed", "investigation_exported"}


def _summary(row: AuditLog) -> str:
    d = row.details or {}
    if row.action == "containment_failed":
        return f"{d.get('action')} failed ({d.get('http_status')}): {d.get('error')}"
    if row.action.startswith("containment_"):
        extra = f" [{d['value']}]" if d.get("value") else ""
        return f"{row.action[len('containment_'):].replace('_', ' ')}{extra}: {d.get('reason', '')}"
    if row.action in _ALERTS:
        return f"severity {d.get('severity')}, confidence {d.get('confidence')}, stage {d.get('stage') or d.get('to_stage')}"
    if row.action == "alert_status_changed":
        return f"alert status {d.get('from')} -> {d.get('to')}"
    if row.action == "investigation_status_changed":
        return f"investigation status -> {d.get('to')}"
    if row.action == "investigation_exported":
        return f"evidence exported as {d.get('format')} ({d.get('events')} events, integrity {'intact' if d.get('integrity_intact') else 'ISSUE'})"
    if row.action == "simulation_step":
        return f"{d.get('step')} ({d.get('status')}) from {d.get('source_ip')}"
    return ", ".join(f"{k}={v}" for k, v in list(d.items())[:4])


def audit_rows(db: Session, category: str | None, limit: int) -> list[dict]:
    people = _employees(db)
    result = []
    for row in db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(1500)):
        actor = people.get(row.actor_id) if row.actor_id else None
        if row.action == "containment_failed":
            cat = "failed_response"
        elif row.action.startswith("containment_"):
            cat = "containment"
        elif row.action in _ALERTS:
            cat = "alerts"
        elif row.action in _INVESTIGATIONS:
            cat = "investigations"
        elif actor is not None and actor.role == "security_admin" or (actor is None and row.action == "database_seeded"):
            cat = "administrator"
        else:
            continue   # ordinary employee activity is in the event feed, not the audit trail
        if category and cat != category:
            continue
        target = people.get(int(row.target_id)) if row.target_type == "employee" and row.target_id and row.target_id.isdigit() else None
        result.append({
            "id": row.id, "timestamp": iso(row.timestamp), "category": cat, "category_label": AUDIT_CATEGORIES.get(cat, cat),
            "action": row.action, "actor": actor.employee_code if actor else "SYSTEM",
            "target": target.employee_code if target else (f"{row.target_type} {row.target_id}" if row.target_type else "-"),
            "summary": _summary(row), "ip": row.ip_address or "-",
        })
        if len(result) >= limit:
            break
    return result
