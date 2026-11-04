"""Event correlation: connects suspicious events into evidence chains and classifies the attack stage.

Events are related when they share a session, an unfamiliar source IP, or a related (created) account. Stages come
from the evidence itself, in any order. Each event counts for at most one independent stage, so the same
evidence is never counted twice.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import rules
from backend.catalog import STAGES
from backend.config import get_settings
from backend.detection_engine import linked_employee_ids, window_events
from backend.models import Employee, SecurityEvent

RANK = {stage: i for i, stage in enumerate(STAGES)}
STRONG_RELATIONS = {"session", "ip", "related_account"}


@dataclass
class Evidence:
    event_id: int
    timestamp: datetime
    employee_id: int
    account: str
    event_type: str
    resource: str | None
    outcome: str
    source_ip: str
    session_id: int | None
    rule: str                    # the strongest rule on this event (the one used for scoring)
    severity: float
    stages: list[str]            # every stage this event supports
    count_stage: str | None      # the single stage this event contributes to the independent-stage count
    rules: list[str] = field(default_factory=list)
    relations: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        """`rule_weight` is the hand-assigned weight of the strongest rule on this event (heuristic; not impact, not a probability)."""
        return {"event_id": self.event_id, "timestamp": self.timestamp.isoformat(), "account": self.account,
                "event_type": self.event_type, "resource": self.resource, "outcome": self.outcome,
                "source_ip": self.source_ip, "session_id": self.session_id, "rule": self.rule, "rules": self.rules,
                "rule_weight": round(self.severity, 3), "stages": self.stages, "relations": self.relations}


@dataclass
class StageHit:
    stage: str
    first_seen: datetime
    last_seen: datetime
    event_ids: list[int]
    rules: list[str]
    strong: bool = False

    def as_dict(self) -> dict:
        return {"stage": self.stage, "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
                "event_ids": self.event_ids, "rules": self.rules, "strongly_linked": self.strong}


@dataclass
class CorrelationResult:
    evidence: list[Evidence]
    stages: list[StageHit]                # all observed stages, in progression order
    stage_history: list[str]              # observed stages in order of first appearance
    current_stage: str                    # most advanced stage supported by evidence ("none" if no evidence)
    counted_stages: int                   # independent stages (an event counts once)
    effective_stages: float               # strongly linked stages count 1.0, weakly linked 0.5 (display only; not scored)
    links: dict
    first_event_id: int | None
    last_event_id: int | None

    @property
    def stage_names(self) -> list[str]:
        return [h.stage for h in self.stages]

    @property
    def is_attack(self) -> bool:
        return self.counted_stages >= 2


def _relation(a: SecurityEvent, b: SecurityEvent, unfamiliar_ips: set[str], parents: dict[int, int | None]) -> str | None:
    if a.session_id is not None and a.session_id == b.session_id:
        return "session"
    if a.source_ip == b.source_ip and a.source_ip in unfamiliar_ips:
        return "ip"
    if parents.get(a.employee_id) == b.employee_id or parents.get(b.employee_id) == a.employee_id:
        return "related_account"
    if a.employee_id == b.employee_id:
        return "same_employee"
    return None


def _flags(event: SecurityEvent) -> list[dict]:
    """Rule flags in the current format; events stored by older versions only had `points`."""
    return [{**f, "severity": f.get("severity", f.get("points", 0) / 100), "stages": f.get("stages", [])}
            for f in (event.risk_flags or [])]


def correlate_events(events: list[SecurityEvent], parents: dict[int, int | None] | None = None) -> CorrelationResult:
    parents = parents or {}
    min_sev = rules.param("min_evidence_severity")
    flags = {e.id: _flags(e) for e in events}
    flagged = [e for e in events if any(f["severity"] >= min_sev or f["stages"] for f in flags[e.id])]
    unfamiliar_ips = {e.source_ip for e in flagged if any(f["rule"] == "unfamiliar_ip" for f in flags[e.id])}

    evidence: list[Evidence] = []
    by_id: dict[int, SecurityEvent] = {}
    for e in flagged:
        top = max(flags[e.id], key=lambda f: f["severity"])
        stages = sorted({s for f in flags[e.id] for s in f["stages"] if s in RANK}, key=RANK.get)
        evidence.append(Evidence(
            e.id, e.timestamp, e.employee_id, e.employee.username, e.event_type, e.resource, e.outcome, e.source_ip,
            e.session_id, top["rule"], top["severity"], stages, stages[-1] if stages else None,
            rules=[f["rule"] for f in flags[e.id]],
        ))
        by_id[e.id] = e

    # relations between evidence events
    strong_pairs: dict[int, set[int]] = {ev.event_id: set() for ev in evidence}
    link_counts: dict[str, int] = {}
    for i, a in enumerate(evidence):
        for b in evidence[i + 1:]:
            rel = _relation(by_id[a.event_id], by_id[b.event_id], unfamiliar_ips, parents)
            if rel is None:
                continue
            link_counts[rel] = link_counts.get(rel, 0) + 1
            if rel in STRONG_RELATIONS:
                strong_pairs[a.event_id].add(b.event_id)
                strong_pairs[b.event_id].add(a.event_id)
                for ev in (a, b):
                    if rel not in ev.relations:
                        ev.relations.append(rel)

    # stage hits (all stages, for classification) and independent stage counting (one stage per event)
    hits: dict[str, StageHit] = {}
    for ev in evidence:
        for stage in ev.stages:
            hit = hits.setdefault(stage, StageHit(stage, ev.timestamp, ev.timestamp, [], []))
            hit.last_seen = max(hit.last_seen, ev.timestamp)
            hit.event_ids.append(ev.event_id)
            for r in ev.rules:
                if r not in hit.rules:
                    hit.rules.append(r)
    counted: dict[str, list[Evidence]] = {}
    for ev in evidence:
        if ev.count_stage:
            counted.setdefault(ev.count_stage, []).append(ev)
    effective = 0.0
    stage_of = {ev.event_id: ev.count_stage for ev in evidence}
    for stage, evs in counted.items():
        strong = any(stage_of.get(other) != stage for ev in evs for other in strong_pairs[ev.event_id])
        if stage in hits:
            hits[stage].strong = strong
        effective += 1.0 if (strong or len(counted) == 1) else 0.5

    ordered = sorted(hits.values(), key=lambda h: RANK[h.stage])
    times = [ev.timestamp for ev in evidence]
    sessions = sorted({ev.session_id for ev in evidence if ev.session_id is not None})
    return CorrelationResult(
        evidence=evidence,
        stages=ordered,
        stage_history=[h.stage for h in sorted(hits.values(), key=lambda h: h.first_seen)],
        current_stage=ordered[-1].stage if ordered else "none",
        counted_stages=len(counted),
        effective_stages=effective,
        links={
            "sessions": sessions,
            "ips": sorted(unfamiliar_ips),
            "accounts": sorted({ev.account for ev in evidence}),
            "relations": link_counts,
        },
        first_event_id=min(evidence, key=lambda ev: (ev.timestamp, ev.event_id)).event_id if evidence else None,
        last_event_id=max(evidence, key=lambda ev: (ev.timestamp, ev.event_id)).event_id if evidence else None,
    )


def correlate(db: Session, employee: Employee, as_of: datetime, events: list[SecurityEvent] | None = None,
              minutes: int | None = None) -> CorrelationResult:
    """Correlate the employee's window (plus related accounts and other accounts using the same suspicious IP)."""
    minutes = minutes or get_settings().correlation_window_minutes
    events = events if events is not None else window_events(db, employee.id, as_of, minutes)
    linked = set(linked_employee_ids(db, employee.id))
    suspicious_ips = {e.source_ip for e in events if any(f["rule"] == "unfamiliar_ip" for f in (e.risk_flags or []))}
    if suspicious_ips:
        others = db.scalars(select(SecurityEvent).where(
            SecurityEvent.source_ip.in_(suspicious_ips), SecurityEvent.employee_id.not_in(linked),
            SecurityEvent.timestamp >= as_of - timedelta(minutes=minutes), SecurityEvent.timestamp <= as_of,
            SecurityEvent.risk_points > 0))
        events = sorted([*events, *others], key=lambda e: (e.timestamp, e.id))
    parents = {eid: parent for eid, parent in db.execute(select(Employee.id, Employee.created_by_id)
                                                          .where(Employee.id.in_({e.employee_id for e in events} or {0})))}
    return correlate_events(events, parents)
