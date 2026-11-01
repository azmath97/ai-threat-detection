"""Hybrid threat engine: combines the ML anomaly score, rule severity, correlated evidence, the behavioural
baseline and the attack stage into one bounded attack-confidence score (0-100).

    confidence = 100 * ( w_ml*ML + w_rules*RULES + w_corr*CORRELATION + w_base*BASELINE + w_stage*STAGE )

Every component is in [0, 1] and the weights sum to 1, so the score can never exceed 100 however many events
arrive. Repeated identical evidence is discounted, and thin evidence (too few independent stages) caps the
severity, so a single unfamiliar IP or one large export cannot be critical on its own.
"""
from dataclasses import dataclass, field
from datetime import datetime
from math import log1p

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import data_exposure, rules
from backend.baseline import baseline_for, to_record
from backend.catalog import STAGE_LABELS
from backend.config import get_settings
from backend.correlation_engine import CorrelationResult, correlate
from backend.database import utcnow
from backend.detection_engine import level_for, window_events
from backend.models import Employee, RiskAssessment, SecurityEvent
from ml.anomaly_detector import AnomalyResult, get_detector
from ml.features import Baseline, extract_features, is_after_hours


@dataclass
class ThreatAssessment:
    employee_id: int
    as_of: datetime
    confidence: float = 0.0
    level: str = "normal"
    components: dict = field(default_factory=dict)
    ml: AnomalyResult | None = None
    features: dict = field(default_factory=dict)
    correlation: CorrelationResult | None = None
    exposure: dict = field(default_factory=dict)
    factors: list[dict] = field(default_factory=list)
    related_accounts: dict[int, str] = field(default_factory=dict)
    suspicious_ips: list[str] = field(default_factory=list)
    capped: bool = False

    @property
    def stage(self) -> str:
        return self.correlation.current_stage if self.correlation else "none"

    @property
    def stage_label(self) -> str:
        return STAGE_LABELS[self.stage]

    @property
    def score(self) -> int:
        """Whole-number score. Floored (never rounded up) so it always falls in the same severity band as `level`."""
        return int(self.confidence)

    @property
    def stage_names(self) -> list[str]:
        return self.correlation.stage_names if self.correlation else []

    @property
    def counted_stages(self) -> int:
        return self.correlation.counted_stages if self.correlation else 0


def _rule_component(corr: CorrelationResult) -> tuple[float, list[dict]]:
    """Noisy-OR over de-duplicated evidence groups. Repeats of the same rule on the same target add little."""
    factor, cap = rules.scoring("repeat_factor"), rules.scoring("repeat_cap")
    groups: dict[tuple, list] = {}
    for ev in corr.evidence:
        if ev.rule not in rules.rules():   # rule from an older version of the configuration
            continue
        target = ev.resource if ev.resource else (ev.source_ip if ev.rule == "unfamiliar_ip" else ev.account)
        groups.setdefault((ev.rule, target), []).append(ev)
    remaining, factors = 1.0, []
    for (rule_id, target), evs in groups.items():
        sev = sorted((e.severity for e in evs), reverse=True)
        value = min(1.0, min(sev[0] + factor * sum(sev[1:]), sev[0] * cap))
        remaining *= 1.0 - value
        factors.append({"rule": rule_id, "target": target, "points": round(value * 100), "count": len(evs),
                        "description": rules.rule(rule_id).description})
    return 1.0 - remaining, sorted(factors, key=lambda f: f["points"], reverse=True)


def _baseline_component(features: dict, baseline: Baseline, events: list[SecurityEvent]) -> float:
    first_login = next((e for e in events if e.event_type == "login"), None)
    off_hours = bool(first_login and is_after_hours(first_login.timestamp)
                     and baseline.after_hours_rate < rules.param("after_hours_baseline_rate_max"))
    ref = max(50.0, baseline.session_download_max)
    volume = max(features["download_volume"], features["external_transfer_volume"])
    volume_dev = min(1.0, max(0.0, (volume - log1p(ref)) / (log1p(ref * 50) - log1p(ref))))
    return min(1.0, 0.30 * features["unfamiliar_ip"] + 0.15 * float(off_hours) + 0.30 * volume_dev
               + 0.25 * min(1.0, features["restricted_access_attempts"] / 4))


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
    base_value = _baseline_component(features, baseline, events)
    stage_value = rules.stage_weight(corr.current_stage)

    values = {"ml": ml.score, "rules": rule_value, "correlation": corr.strength, "baseline": base_value, "stage": stage_value}
    w = rules.weights()
    confidence = 100.0 * sum(w[name] * values[name] for name in values)

    capped = False
    cap = None
    if corr.counted_stages < rules.scoring("min_stages_for_high_risk"):
        cap = s.threat_high_threshold - 0.01
    elif corr.counted_stages < rules.scoring("min_stages_for_critical"):
        cap = s.threat_critical_threshold - 0.01
    if cap is not None and confidence > cap:
        confidence, capped = cap, True
    confidence = round(min(100.0, max(0.0, confidence)), 2)

    result.confidence = confidence
    result.level = level_for(confidence)
    result.ml, result.features, result.correlation, result.factors, result.capped = ml, features, corr, factors, capped
    result.components = {
        **{name: {"value": round(values[name], 4), "weight": round(w[name], 4), "contribution": round(100 * w[name] * values[name], 2)}
           for name in values},
        "independent_stages": corr.counted_stages, "capped_by_stage_count": capped,
    }
    result.exposure = data_exposure.assess(events, result.level != "normal")
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
    )


def assess_and_store(db: Session, employee: Employee, event: SecurityEvent) -> tuple[ThreatAssessment, RiskAssessment]:
    threat = assess(db, employee, event.timestamp)
    row = to_row(threat, event)
    db.add(row)
    db.flush()
    return threat, row


def assess_all(db: Session, as_of: datetime | None = None) -> dict[int, ThreatAssessment]:
    """Current assessment of every employee (employees without recent activity are normal by definition)."""
    as_of = as_of or utcnow()
    return {e.id: assess(db, e, as_of) for e in db.scalars(select(Employee).order_by(Employee.id))}


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
        add("lock_account", "high", "Critical confidence; lock the account pending identity verification",
            target=None)
    if exposure["external_transfer_confirmed"]:
        add("escalate_incident", "immediate", "Confirmed external transfer: start incident response and review "
            "data-breach notification obligations", executable=False)
    return actions
