"""Correlates individual risky events into an attack chain (kill-chain stages)."""
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.detection_engine import window_events
from backend.models import SecurityEvent

STAGES = ["initial_access", "discovery", "privilege_escalation", "collection", "exfiltration"]

RULE_STAGE = {
    "failed_login_burst": "initial_access",
    "login_after_failures": "initial_access",
    "unfamiliar_ip": "initial_access",  # only when seen on a login event
    "access_denied": "discovery",
    "rapid_enumeration": "discovery",
    "restricted_denied": "privilege_escalation",
    "permission_change_attempt": "privilege_escalation",
    "privileged_account_created": "privilege_escalation",
    "new_account_login": "privilege_escalation",
    "sensitive_access": "collection",
    "bulk_download": "collection",
    "data_export": "exfiltration",
    "external_transfer": "exfiltration",
}


@dataclass
class StageHit:
    stage: str
    first_seen: datetime
    event_ids: list[int] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)


@dataclass
class CorrelationResult:
    stages: list[StageHit]
    confidence: float
    is_attack: bool
    highest_stage: str

    @property
    def stage_names(self) -> list[str]:
        return [h.stage for h in self.stages]

    def stages_for_event(self, event_id: int) -> list[str]:
        return [h.stage for h in self.stages if event_id in h.event_ids]


def stages_for_event(event: SecurityEvent) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for flag in event.risk_flags or []:
        rule = flag["rule"]
        stage = RULE_STAGE.get(rule)
        if stage is None:
            continue
        if rule == "unfamiliar_ip" and event.event_type != "login":
            continue
        found.setdefault(stage, []).append(rule)
    return found


def correlate_events(events: list[SecurityEvent]) -> CorrelationResult:
    hits: dict[str, StageHit] = {}
    for ev in events:
        for stage, rules in stages_for_event(ev).items():
            hit = hits.setdefault(stage, StageHit(stage, ev.timestamp))
            hit.event_ids.append(ev.id)
            for rule in rules:
                if rule not in hit.rules:
                    hit.rules.append(rule)

    ordered = sorted(hits.values(), key=lambda h: STAGES.index(h.stage))
    n = len(ordered)
    progressive = n >= 2 and all(a.first_seen <= b.first_seen for a, b in zip(ordered, ordered[1:]))
    confidence = round(min(0.99, 0.2 * n + (0.15 if progressive else 0.0)), 2) if n else 0.0
    return CorrelationResult(
        stages=ordered,
        confidence=confidence,
        is_attack=n >= 2,
        highest_stage=ordered[-1].stage if ordered else "none",
    )


def correlate(db: Session, employee_id: int, as_of: datetime, minutes: int | None = None) -> CorrelationResult:
    minutes = minutes or get_settings().correlation_window_minutes
    return correlate_events(window_events(db, employee_id, as_of, minutes))
