"""Evidence export: a self-contained report for one investigation.

Only evidence belonging to the investigation is included. Events come from the preserved snapshots (not re-read from
the live table) and are marked verified/modified/missing by comparing each snapshot's SHA-256 with the live event.
"""
import csv
import hashlib
import io
import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import investigation_service, scoring
from backend.catalog import SEVERITY_LABELS, STAGE_LABELS, STAGES
from backend.config import get_settings, to_local
from backend.database import utcnow
from backend.detection_engine import linked_employee_ids
from backend.models import (
    AttackInvestigation,
    ContainmentAction,
    Employee,
    InvestigationEvidence,
    RiskAssessment,
    SecurityAlert,
)

FORMAT_VERSION = "1.0"
CSV_COLUMNS = ["investigation_id", "event_id", "timestamp_utc", "timestamp_local", "employee_id", "account", "session_id", "event_type",
               "resource", "outcome", "source_ip", "device_info", "records_accessed", "records_downloaded", "synthetic", "rules",
               "relations", "risk_points", "integrity", "sha256"]


def _times(dt) -> dict:
    return {"utc": dt.isoformat() if dt else None, "local": to_local(dt).isoformat() if dt else None}


def _event_row(row: InvestigationEvidence, state: str) -> dict:
    s = row.snapshot
    stamp = datetime.fromisoformat(s["timestamp"])
    return {
        "event_id": s["event_id"], "timestamp": _times(stamp), "employee_id": s["employee_id"], "account": s["account"],
        "session_id": s["session_id"], "event_type": s["event_type"], "resource": s["resource"], "outcome": s["outcome"],
        "source_ip": s["source_ip"], "device_info": s["device_info"], "records_accessed": s["records_accessed"],
        "records_downloaded": s["records_downloaded"], "synthetic": s["is_synthetic"], "scenario": s["scenario"],
        "risk_points": s["risk_points"], "rules": [f["rule"] for f in s["risk_flags"]],
        "stages": sorted({st for f in s["risk_flags"] for st in f.get("stages", [])}),
        "relations": list(row.relations or []), "details": s["details"], "integrity": state, "sha256": row.content_hash,
        "collected_at": _times(row.collected_at),
    }


def build(db: Session, investigation: AttackInvestigation, admin: Employee) -> dict:
    inv = investigation
    employee = inv.employee
    rows = investigation_service.evidence_rows(db, inv.id)
    integrity = investigation_service.integrity(db, inv)
    bad = {*integrity["modified"], *integrity["missing"]}
    states = {r.event_id: ("modified" if r.event_id in integrity["modified"] else "missing" if r.event_id in integrity["missing"]
                           else "verified") for r in rows}
    events = sorted((_event_row(r, states[r.event_id]) for r in rows), key=lambda e: (e["timestamp"]["utc"], e["event_id"]))
    event_ids = [e["event_id"] for e in events]

    codes = {e.id: e.employee_code for e in db.scalars(select(Employee))}
    alert = db.scalar(select(SecurityAlert).where(SecurityAlert.investigation_id == inv.id).order_by(SecurityAlert.id.desc()))
    linked = linked_employee_ids(db, employee.id)
    actions = db.scalars(select(ContainmentAction).where(
        (ContainmentAction.investigation_id == inv.id) |
        ((ContainmentAction.investigation_id.is_(None)) & ContainmentAction.employee_id.in_(linked)
         & (ContainmentAction.created_at >= inv.created_at)
         & (ContainmentAction.created_at <= (inv.closed_at or utcnow())))
    ).order_by(ContainmentAction.id)).all()
    assessments = db.scalars(select(RiskAssessment).where(
        RiskAssessment.employee_id == employee.id, RiskAssessment.event_id.in_(event_ids or [0])).order_by(RiskAssessment.id)).all()

    lanes = []
    for stage in STAGES:
        evs = [e for e in events if stage in e["stages"]]
        lanes.append({"stage": stage, "label": STAGE_LABELS[stage], "reached": bool(evs), "current": stage == inv.attack_stage,
                      "event_ids": [e["event_id"] for e in evs], "first_seen": evs[0]["timestamp"] if evs else None,
                      "last_seen": evs[-1]["timestamp"] if evs else None})

    case = inv.case_file or {}
    level = scoring.stored_band(inv.explanation, inv.risk_score_exact)
    first = next((e for e in events if e["event_id"] == inv.first_event_id), None)
    latest = next((e for e in events if e["event_id"] == inv.latest_event_id), None)
    brief = lambda e: None if e is None else {"event_id": e["event_id"], "timestamp": e["timestamp"], "event_type": e["event_type"],
                                               "resource": e["resource"], "source_ip": e["source_ip"]}
    report = {
        "report": {
            "format_version": FORMAT_VERSION, "generated_at": _times(utcnow()), "generated_by": admin.employee_code,
            "timezone": get_settings().display_timezone, "investigation_id": inv.id,
            "synthetic": inv.is_synthetic or any(e["synthetic"] for e in events),
            "notice": ("Synthetic data from a local simulation. Containment actions affected only the simulated environment, "
                       "not a real banking network." if inv.is_synthetic else "Evidence export for a single investigation.")
                      + " Containment actions in this report are simulations that changed only this application's own records.",
        },
        "incident_summary": {
            "investigation_id": inv.id, "employee_id": employee.employee_code, "department": employee.department,
            "job_role": employee.job_role, "status": inv.status, "created_at": _times(inv.created_at),
            "updated_at": _times(inv.updated_at), "resolved_at": _times(inv.closed_at),
            "heuristic_risk_score": inv.risk_score_exact, "risk_score_note": "hand-weighted evidence score 0-100; not a probability",
            "risk_band": level, "risk_band_label": SEVERITY_LABELS[level],
            "impact_severity": inv.impact_severity, "evidence_strength": inv.evidence_strength,
            "current_stage": inv.attack_stage, "current_stage_label": STAGE_LABELS.get(inv.attack_stage, inv.attack_stage),
            "attack_type": (inv.explanation or {}).get("attack_type"), "summary": inv.summary,
            "first_suspicious_event": brief(first), "latest_suspicious_event": brief(latest),
            "sessions": case.get("sessions", []), "suspicious_ips": case.get("suspicious_ips", []),
            "related_accounts": case.get("related_accounts", []), "sensitive_resources": case.get("sensitive_resources", []),
            "alert": None if alert is None else {
                "alert_id": alert.id, "risk_band": alert.severity, "impact_severity": alert.impact_severity,
                "evidence_strength": alert.evidence_strength, "status": alert.status, "title": alert.title,
                "detected_at": _times(alert.detected_at), "triggering_event_id": alert.event_id,
                "first_event_id": alert.first_event_id, "peak_heuristic_risk_score": alert.peak_risk_score,
                "score_basis": alert.score_basis},
        },
        "attack_timeline": {"stages": lanes, "events": [{k: e[k] for k in ("event_id", "timestamp", "account", "event_type", "resource",
                                                                         "outcome", "source_ip", "stages", "rules")} for e in events]},
        "correlated_events": events,
        "risk_score_history": [{"assessment_id": a.id, "event_id": a.event_id, "timestamp": _times(a.created_at), "heuristic_risk_score": a.score,
                                "risk_band": a.level, "impact_severity": a.impact_severity, "evidence_strength": a.evidence_strength,
                                "stage": a.stage, "anomaly_score": a.ml_score} for a in assessments],
        "data_exposure_assessment": {**(inv.exposure or {}), "case_totals": case.get("data", {})},
        "containment_actions": [{"action_id": a.id, "action": a.action_type, "target_employee_id": codes.get(a.employee_id),
                                 "investigation_id": a.investigation_id, "alert_id": a.alert_id, "status": a.status,
                                 "status_label": a.status_label, "simulated": True, "scope": a.scope, "reason": a.reason,
                                 "result": a.result, "performed_by": codes.get(a.performed_by), "timestamp": _times(a.created_at),
                                 "details": a.details}
                                for a in actions],
        "investigation_findings": inv.explanation,
        "evidence_integrity": {**integrity, "events_with_issues": sorted(bad)},
    }
    return report


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False, default=str)


def _safe(value) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text      # neutralise spreadsheet formulas


def to_csv(report: dict) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    inv_id = report["report"]["investigation_id"]
    for e in report["correlated_events"]:
        writer.writerow([_safe(v) for v in (
            inv_id, e["event_id"], e["timestamp"]["utc"], e["timestamp"]["local"], e["employee_id"], e["account"], e["session_id"],
            e["event_type"], e["resource"], e["outcome"], e["source_ip"], e["device_info"], e["records_accessed"],
            e["records_downloaded"], e["synthetic"], ";".join(e["rules"]), ";".join(e["relations"]), e["risk_points"],
            e["integrity"], e["sha256"])])
    return out.getvalue()


def checksum(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
