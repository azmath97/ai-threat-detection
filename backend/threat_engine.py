"""Threat engine: turns a window of one employee's events into a heuristic risk score, a risk band, an impact severity and an
evidence-strength reading, together with the evidence behind them.

The four quantities and the arithmetic are defined in backend/scoring.py. In short:

    risk_score = 100 x (w_rules x rule_evidence + w_ml x anomaly_score)         (heuristic, 0-100, not a probability)

Every component is in [0, 1] and the weights sum to 1, so the score cannot exceed 100 however many events arrive. Stage,
correlation and baseline deviation are not added to the score (they restate the same rule evidence); the number of
independent stages gates the risk band instead.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import expm1

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import data_exposure, rules, scoring
from backend.baseline import baseline_for, to_record
from backend.catalog import STAGE_LABELS
from backend.config import get_settings
from backend.correlation_engine import CorrelationResult, correlate
from backend.database import utcnow
from backend.detection_engine import window_events
from backend.models import Employee, RiskAssessment, SecurityEvent
from ml.anomaly_detector import AnomalyResult, get_detector
from ml.features import Baseline, extract_features


@dataclass
class ThreatAssessment:
    employee_id: int
    as_of: datetime
    risk_score: float = 0.0                 # heuristic, 0-100, not a probability
    level: str = "normal"                   # risk band (stored name kept for compatibility)
    band_gated: bool = False                # the corroboration gate lowered the band below what the score alone implies
    impact: dict = field(default_factory=lambda: {"level": "none", "label": "None", "reasons": []})
    strength: dict = field(default_factory=lambda: {"level": "none", "label": "No evidence", "model_agrees": False, "reasons": []})
    components: dict = field(default_factory=dict)
    breakdown: dict = field(default_factory=dict)
    ml: AnomalyResult | None = None
    features: dict = field(default_factory=dict)
    correlation: CorrelationResult | None = None
    exposure: dict = field(default_factory=dict)
    factors: list[dict] = field(default_factory=list)
    related_accounts: dict[int, str] = field(default_factory=dict)
    suspicious_ips: list[str] = field(default_factory=list)

    @property
    def stage(self) -> str:
        return self.correlation.current_stage if self.correlation else "none"

    @property
    def stage_label(self) -> str:
        return STAGE_LABELS[self.stage]

    @property
    def score(self) -> int:
        """Whole-number score, floored so it never reads higher than the exact value."""
        return int(self.risk_score)

    @property
    def impact_severity(self) -> str:
        return self.impact["level"]

    @property
    def evidence_strength(self) -> str:
        return self.strength["level"]

    @property
    def stage_names(self) -> list[str]:
        return self.correlation.stage_names if self.correlation else []

    @property
    def counted_stages(self) -> int:
        return self.correlation.counted_stages if self.correlation else 0


def _rule_component(corr: CorrelationResult) -> tuple[float, list[dict]]:
    """Noisy-OR over de-duplicated evidence groups.

    * An event is evidence once, through its strongest rule, however many times it appears in the list.
    * Events with the same rule on the same target form one group whose value is its strongest weight plus a discounted
      share of the others (`repeat_factor`), never more than `repeat_cap` times the strongest.
    Returns the rule evidence (0-1) and the groups, each with the events behind it."""
    factor, cap = rules.scoring("repeat_factor"), rules.scoring("repeat_cap")
    groups: dict[tuple, list] = {}
    seen: set[int] = set()
    for ev in corr.evidence:
        if ev.event_id in seen or ev.rule not in rules.rules():    # duplicate evidence, or a rule removed from the configuration
            continue
        seen.add(ev.event_id)
        target = ev.resource if ev.resource else (ev.source_ip if ev.rule == "unfamiliar_ip" else ev.account)
        groups.setdefault((ev.rule, target), []).append(ev)
    remaining, factors = 1.0, []
    for (rule_id, target), evs in groups.items():
        sev = sorted((e.severity for e in evs), reverse=True)
        value = min(1.0, min(sev[0] + factor * sum(sev[1:]), sev[0] * cap))
        remaining *= 1.0 - value
        factors.append({
            "rule": rule_id, "target": target, "points": round(value * 100), "count": len(evs),
            "description": rules.rule(rule_id).description,
            "rule_weight": round(sev[0], 3), "counted_weight": round(value, 3),
            "event_ids": [e.event_id for e in evs],
            "first_seen": min(e.timestamp for e in evs).isoformat(), "last_seen": max(e.timestamp for e in evs).isoformat(),
        })
    return 1.0 - remaining, sorted(factors, key=lambda f: f["points"], reverse=True)


def _feature_deviations(features: dict, baseline: Baseline, corr: CorrelationResult) -> list[dict]:
    """The model's input features for this window next to what is normal for this employee, so an analyst can see
    what the anomaly score is reacting to. `deviates` is a plain comparison, not a statistical test."""
    s = get_settings()
    downloaded, transferred = expm1(features["download_volume"]), expm1(features["external_transfer_volume"])
    return [
        {"feature": "download_volume", "label": "Records downloaded or exported", "value": round(downloaded),
         "reference": f"largest earlier session: {round(baseline.session_download_max):,}",
         "deviates": downloaded > max(s.bulk_record_threshold / 5, baseline.session_download_max * 3)},
        {"feature": "external_transfer_volume", "label": "Records sent to external destinations", "value": round(transferred),
         "reference": f"earlier external transfers: {baseline.external_transfer_count}", "deviates": transferred > 0},
        {"feature": "unfamiliar_ip", "label": "Source address outside the employee's known addresses", "value": bool(features["unfamiliar_ip"]),
         "reference": "known addresses: " + (", ".join(sorted(baseline.known_ips)) or "none"),
         "deviates": bool(features["unfamiliar_ip"]), "addresses": corr.links.get("ips", [])},
        {"feature": "restricted_access_attempts", "label": "Denied or first-time restricted-resource attempts",
         "value": int(features["restricted_access_attempts"]), "reference": "expected: 0", "deviates": features["restricted_access_attempts"] > 0},
        {"feature": "failed_login_count", "label": "Failed logins", "value": int(features["failed_login_count"]),
         "reference": "expected: 0 to 1", "deviates": features["failed_login_count"] >= 3},
        {"feature": "departments_accessed", "label": "Other departments' resources attempted", "value": int(features["departments_accessed"]),
         "reference": f"home department: {baseline.home_department}", "deviates": features["departments_accessed"] > 2},
        {"feature": "privilege_escalation", "label": "Administrative or permission change attempted",
         "value": bool(features["privilege_escalation"]), "reference": "expected: no", "deviates": bool(features["privilege_escalation"])},
        {"feature": "login_hour", "label": "Local hour of first login", "value": round(features["login_hour"], 1),
         "reference": f"business hours {s.business_hours_start}-{s.business_hours_end}; after-hours rate "
                      f"{baseline.after_hours_rate:.0%} of earlier logins",
         "deviates": bool(features["login_hour"] < s.business_hours_start or features["login_hour"] >= s.business_hours_end)
                     and baseline.after_hours_rate < rules.param("after_hours_baseline_rate_max")},
    ]


def _breakdown(*, values: dict, weights: dict, groups: list[dict], ml: AnomalyResult, features: dict, baseline: Baseline,
               corr: CorrelationResult, as_of: datetime, window_minutes: int, score: float, by_score: str, band: str,
               gated: bool, ignored: list[dict]) -> dict:
    s = get_settings()
    stages = corr.counted_stages
    return {
        "kind": "heuristic",
        "not_a_probability": True,
        "formula": scoring.SCORE_FORMULA,
        "risk_score": score,
        "window": {"start": (as_of - timedelta(minutes=window_minutes)).isoformat(), "end": as_of.isoformat(),
                   "minutes": window_minutes},
        "components": [
            {"key": "rules", "label": "Rule evidence", "kind": "hand-assigned rule weights, combined by noisy-OR",
             "value": round(values["rules"], 4), "weight": round(weights["rules"], 4),
             "contribution": round(100 * weights["rules"] * values["rules"], 2)},
            {"key": "ml", "label": "Anomaly score", "kind": "Isolation Forest output rescaled to normal training behaviour (not a probability)"
             if ml.mode == "isolation_forest" else "heuristic fallback (no trained model loaded; not a probability)",
             "value": round(values["ml"], 4), "weight": round(weights["ml"], 4),
             "contribution": round(100 * weights["ml"] * values["ml"], 2)},
        ],
        "rule_evidence": groups,
        "ignored_evidence": ignored,
        "counting_rule": ("Each event counts once, through its strongest rule. Repeats of one rule on one target add "
                          f"{rules.scoring('repeat_factor'):.0%} of their weight each, up to {rules.scoring('repeat_cap')}x the strongest."),
        "model": {**ml.as_dict(), "role": "A separate anomaly model. It sees the same events as the rules, so its weight is small "
                                           "and it never lifts the corroboration gate."},
        "feature_deviations": _feature_deviations(features, baseline, corr),
        "not_added_to_the_score": ["attack stage", "correlation strength", "baseline deviation",
                                   "(they restate the rule evidence; stage count gates the band instead)"],
        "gate": {"independent_stages": stages, "stages": corr.stage_names,
                 "needed_for_elevated": rules.scoring("min_stages_for_high_risk"),
                 "needed_for_alert": rules.scoring("min_stages_for_critical"),
                 "band_from_score_alone": by_score, "band": band, "lowered_by_gate": gated},
        "thresholds": {"watch": s.threat_suspicious_threshold, "elevated": s.threat_high_threshold, "alert": s.threat_critical_threshold,
                       "source": s.thresholds_source},
    }


def assess(db: Session, employee: Employee, as_of: datetime | None = None) -> ThreatAssessment:
    """Full assessment of an employee (and accounts they created) over the correlation window ending at `as_of`."""
    s = get_settings()
    as_of = as_of or utcnow()
    events = window_events(db, employee.id, as_of, s.correlation_window_minutes)
    result = ThreatAssessment(employee_id=employee.id, as_of=as_of)
    if not events:
        result.exposure = data_exposure.assess([], False)
        return result

    baseline = baseline_for(db, employee, as_of)
    corr = correlate(db, employee, as_of, events=events)
    features = extract_features([to_record(e) for e in events], baseline)
    ml = get_detector().score(features)
    rule_value, factors = _rule_component(corr)

    values = {"rules": rule_value, "ml": ml.score}
    w = rules.weights()
    risk_score = scoring.combine(values, w)
    band, by_score, gated = scoring.band_for(risk_score, corr.counted_stages)

    counted_ids = {i for f in factors for i in f["event_ids"]}
    ignored = [{"event_id": ev.event_id, "rule": ev.rule, "reason": "rule disabled or removed from the configuration"}
               for ev in corr.evidence if ev.event_id not in counted_ids]

    result.risk_score, result.level, result.band_gated = risk_score, band, gated
    result.ml, result.features, result.correlation, result.factors = ml, features, corr, factors
    result.components = {
        **{name: {"value": round(values[name], 4), "weight": round(w[name], 4), "contribution": round(100 * w[name] * values[name], 2)}
           for name in values},
        "independent_stages": corr.counted_stages, "band_gated": gated,
    }
    result.exposure = data_exposure.assess(events, band != "normal")
    result.impact = scoring.impact_severity(result.exposure, corr.stage_names, bool(factors))
    result.strength = scoring.evidence_strength(rule_groups=len(factors), counted_stages=corr.counted_stages,
                                                ml_score=ml.score, ml_mode=ml.mode)
    result.breakdown = _breakdown(values=values, weights=w, groups=factors, ml=ml, features=features, baseline=baseline, corr=corr,
                                  as_of=as_of, window_minutes=s.correlation_window_minutes, score=risk_score, by_score=by_score,
                                  band=band, gated=gated, ignored=ignored)
    result.components.update(impact_severity=result.impact["level"], evidence_strength=result.strength["level"])
    result.related_accounts = {e.employee_id: e.employee.username for e in events if e.employee_id != employee.id}
    # Addresses worth blocking: unfamiliar to this employee and not a colleague's registered workstation.
    colleague_ips = {ip for ips in db.scalars(select(Employee.known_ips).where(Employee.id != employee.id)) for ip in (ips or [])}
    result.suspicious_ips = [ip for ip in corr.links["ips"] if ip not in colleague_ips and not ip.startswith("127.")]
    return result


def to_row(threat: ThreatAssessment, event: SecurityEvent | None) -> RiskAssessment:
    return RiskAssessment(
        employee_id=threat.employee_id, event_id=event.id if event else None, score=threat.score, level=threat.level,
        factors=threat.factors[:8], ml_score=threat.ml.score if threat.ml else 0.0, stage=threat.stage,
        components=threat.components, exposure=threat.exposure, created_at=event.timestamp if event else threat.as_of,
        impact_severity=threat.impact["level"], evidence_strength=threat.strength["level"],
    )


def assess_and_store(db: Session, employee: Employee, event: SecurityEvent) -> tuple[ThreatAssessment, RiskAssessment]:
    threat = assess(db, employee, event.timestamp)
    row = to_row(threat, event)
    db.add(row)
    db.flush()
    return threat, row


def _idle(employee_id: int, as_of: datetime) -> ThreatAssessment:
    result = ThreatAssessment(employee_id=employee_id, as_of=as_of)
    result.exposure = data_exposure.assess([], False)
    return result


def assess_all(db: Session, as_of: datetime | None = None) -> dict[int, ThreatAssessment]:
    """Current assessment of every employee. Only employees with events in the correlation window (and the creators of
    those accounts) are assessed; the rest are normal by definition, so the cost follows recent activity, not history."""
    as_of = as_of or utcnow()
    since = as_of - timedelta(minutes=get_settings().correlation_window_minutes)
    employees = {e.id: e for e in db.scalars(select(Employee).order_by(Employee.id))}
    active = set(db.scalars(select(SecurityEvent.employee_id).where(
        SecurityEvent.timestamp >= since, SecurityEvent.timestamp <= as_of).distinct()))
    active |= {employees[i].created_by_id for i in active if i in employees and employees[i].created_by_id}
    return {i: assess(db, e, as_of) if i in active else _idle(i, as_of) for i, e in employees.items()}


def recommend_actions(threat: ThreatAssessment) -> list[dict]:
    """Containment recommendations driven by stage, exposure and related accounts."""
    s = get_settings()
    if threat.level == "normal" or threat.correlation is None:
        return [{"action": "monitor", "priority": "low", "executable": False, "target": None, "target_employee_id": None,
                 "reason": "No malicious pattern; continue routine monitoring"}]
    stages, exposure = set(threat.stage_names), threat.exposure
    actions: list[dict] = []

    def add(action, priority, reason, *, target=None, target_id=None, executable=True):
        actions.append({"action": action, "priority": priority, "reason": reason, "executable": executable,
                        "target": target, "target_employee_id": target_id or threat.employee_id})

    if threat.level in ("high_risk", "critical") or threat.counted_stages >= 2:
        add("revoke_sessions", "immediate", "Terminate sessions that may be controlled by an attacker")
    if stages & {"collection", "exfiltration", "privilege_escalation"} or exposure["status"] != "none":
        add("restrict_access", "immediate", "Remove confidential and restricted access to stop further collection")
    for ip in threat.suspicious_ips:
        add("block_ip", "immediate", f"Block unfamiliar source address {ip} used throughout the incident", target=ip)
    for account_id, username in threat.related_accounts.items():
        add("lock_account", "immediate", f"Account {username} was created during the incident (persistence)",
            target=username, target_id=account_id)
    if stages & {"privilege_escalation", "persistence"}:
        add("remove_privileges", "high", "Strip elevated (write) privileges gained or used during the incident")
    if threat.level == "critical":
        systems = []
        for ev in threat.correlation.evidence:
            if ev.resource and ({"large_export", "unusual_outbound_transfer"} & set(ev.rules)):
                systems.append(ev.resource)
            if {"admin_console_login_failed", "privileged_account_created"} & set(ev.rules):
                systems.append("it-admin-console")
        for system in dict.fromkeys(systems):
            add("isolate_system", "high", f"Isolate {system}: it was targeted during the incident", target=system)
    if threat.level == "critical" or exposure["external_transfer_confirmed"]:
        add("lock_account", "high", "Alert-level risk band; lock the account pending identity verification",
            target=None)
    if exposure["external_transfer_confirmed"]:
        add("escalate_incident", "immediate", "Confirmed external transfer: start incident response and review "
            "data-breach notification obligations", executable=False)
    return actions
