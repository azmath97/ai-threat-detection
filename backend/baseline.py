"""Per-employee behavioural baseline built from stored history (events before the window being assessed)."""
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.models import Employee, SecurityEvent
from ml.features import Baseline, EventRecord, build_baseline

_CACHE: dict[tuple, Baseline] = {}


def to_record(event: SecurityEvent) -> EventRecord:
    return EventRecord(
        timestamp=event.timestamp, event_type=event.event_type, source_ip=event.source_ip, resource=event.resource,
        outcome=event.outcome, records_accessed=event.records_accessed, records_downloaded=event.records_downloaded,
        session_id=event.session_id, account=event.employee.username if event.employee else str(event.employee_id),
        details=event.details or {},
    )


def baseline_for(db: Session, employee: Employee, as_of: datetime) -> Baseline:
    """History = the employee's own events from BASELINE_DAYS up to the start of the correlation window.

    The recent window is excluded so that an attacker's own activity cannot become part of "normal".
    """
    s = get_settings()
    permissions = {p.resource: p.access_level for p in employee.permissions}
    key = (employee.id, int(as_of.timestamp() // 60), tuple(sorted(permissions.items())), tuple(sorted(employee.known_ips or [])))
    cached = _CACHE.get(key)
    if cached is not None:
        return cached

    until = as_of - timedelta(minutes=s.correlation_window_minutes)
    history = db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.employee_id == employee.id,
            SecurityEvent.timestamp >= as_of - timedelta(days=s.baseline_days),
            SecurityEvent.timestamp < until,
        ).order_by(SecurityEvent.timestamp)
    ).all()
    baseline = build_baseline(
        [to_record(e) for e in history], home_department=employee.department,
        known_ips=employee.known_ips or [], permissions=permissions,
    )
    baseline.created_by_other = employee.created_by_id is not None
    if employee.created_at is not None:
        baseline.account_age_hours = (as_of - employee.created_at).total_seconds() / 3600
    if len(_CACHE) > 512:
        _CACHE.clear()
    _CACHE[key] = baseline
    return baseline


def clear_cache() -> None:
    _CACHE.clear()
