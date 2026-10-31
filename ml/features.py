"""Behavioural feature extraction.

The same code turns a window of events into a feature vector for training (synthetic data) and for live
scoring (events read from the database), so the model always sees consistent features.
"""
from dataclasses import dataclass, field
from datetime import datetime
from math import log1p
from zoneinfo import ZoneInfo

from backend.catalog import RESOURCE_EVENT_TYPES, RESOURCES, is_self_service, sensitivity_of
from backend.config import get_settings

FEATURE_NAMES = [
    "login_hour",                 # local hour of the first login in the window (fractional)
    "unfamiliar_ip",              # 1 if any event came from an IP outside the employee's baseline
    "failed_login_count",
    "resources_accessed",         # distinct classified resources attempted
    "departments_accessed",       # distinct owning departments attempted
    "download_volume",            # log1p(records downloaded / exported)
    "restricted_access_attempts", # denied attempts, or first-time restricted access outside normal duties
    "privilege_escalation",       # 1 if an administrative action or permission change was attempted
    "external_transfer_volume",   # log1p(records sent to external destinations)
    "denied_access_count",
]


@dataclass(frozen=True)
class EventRecord:
    """Database-independent view of a security event."""

    timestamp: datetime
    event_type: str
    source_ip: str
    resource: str | None = None
    outcome: str = "success"
    records_accessed: int = 0
    records_downloaded: int = 0
    session_id: int | None = None
    account: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class Baseline:
    """What is normal for one employee, learnt from their earlier activity and permissions."""

    home_department: str = ""
    known_ips: set[str] = field(default_factory=set)
    permissions: dict[str, str] = field(default_factory=dict)
    typical_resources: set[str] = field(default_factory=set)
    after_hours_rate: float = 0.0
    session_download_max: float = 0.0
    session_download_mean: float = 0.0
    external_transfer_count: int = 0
    login_count: int = 0
    account_age_hours: float | None = None
    created_by_other: bool = False


def is_after_hours(ts: datetime, tz: ZoneInfo | None = None) -> bool:
    s = get_settings()
    local = ts.astimezone(tz or s.tz)
    return local.weekday() >= 5 or not (s.business_hours_start <= local.hour < s.business_hours_end)


def _is_success_download(e: EventRecord) -> bool:
    return e.outcome == "success" and e.event_type in ("file_download", "data_export")


def build_baseline(
    history: list[EventRecord],
    *,
    home_department: str,
    known_ips: list[str] | set[str],
    permissions: dict[str, str],
    tz: ZoneInfo | None = None,
) -> Baseline:
    """Summarise earlier activity (events before the window being assessed)."""
    logins = [e for e in history if e.event_type == "login" and e.outcome == "success"]
    ip_logins: dict[str, int] = {}
    for e in logins:
        ip_logins[e.source_ip] = ip_logins.get(e.source_ip, 0) + 1
    known = set(known_ips) | {ip for ip, n in ip_logins.items() if n >= 2}

    typical = {
        e.resource for e in history
        if e.resource and e.outcome == "success" and e.event_type in RESOURCE_EVENT_TYPES and not is_self_service(e.resource)
    }
    per_session: dict[object, int] = {}
    for e in history:
        if _is_success_download(e):
            key = e.session_id if e.session_id is not None else e.timestamp.date()
            per_session[key] = per_session.get(key, 0) + e.records_downloaded
    values = list(per_session.values())
    return Baseline(
        home_department=home_department,
        known_ips=known,
        permissions=dict(permissions),
        typical_resources=typical,
        after_hours_rate=(sum(is_after_hours(e.timestamp, tz) for e in logins) / len(logins)) if logins else 0.0,
        session_download_max=float(max(values)) if values else 0.0,
        session_download_mean=float(sum(values) / len(values)) if values else 0.0,
        external_transfer_count=sum(1 for e in history if e.event_type == "external_transfer" and e.outcome == "success"),
        login_count=len(logins),
    )


def _attempts(events: list[EventRecord]) -> list[EventRecord]:
    return [e for e in events if e.event_type in RESOURCE_EVENT_TYPES and e.resource in RESOURCES and not is_self_service(e.resource)]


def extract_features(events: list[EventRecord], baseline: Baseline, tz: ZoneInfo | None = None) -> dict[str, float]:
    """Feature dictionary (keys = FEATURE_NAMES) for one window of events belonging to one person."""
    tz = tz or get_settings().tz
    ordered = sorted(events, key=lambda e: e.timestamp)
    first_login = next((e for e in ordered if e.event_type == "login"), ordered[0] if ordered else None)
    hour = 12.0
    if first_login is not None:
        local = first_login.timestamp.astimezone(tz)
        hour = local.hour + local.minute / 60

    attempts = _attempts(ordered)
    restricted = 0
    for e in attempts:
        if e.outcome == "denied":
            restricted += 1
        elif (e.outcome == "success" and sensitivity_of(e.resource) >= 3 and e.resource not in baseline.typical_resources
              and RESOURCES[e.resource]["department"] != baseline.home_department):
            restricted += 1

    return {
        "login_hour": hour,
        "unfamiliar_ip": float(any(e.source_ip not in baseline.known_ips for e in ordered)),
        "failed_login_count": float(sum(e.event_type == "login_failed" for e in ordered)),
        "resources_accessed": float(len({e.resource for e in attempts})),
        "departments_accessed": float(len({RESOURCES[e.resource]["department"] for e in attempts} - {"All"})),
        "download_volume": log1p(sum(e.records_downloaded for e in ordered if _is_success_download(e))),
        "restricted_access_attempts": float(restricted),
        "privilege_escalation": float(any(e.event_type in ("administrative_action", "permission_change_attempt") for e in ordered)),
        "external_transfer_volume": log1p(sum(e.records_downloaded for e in ordered if e.event_type == "external_transfer")),
        "denied_access_count": float(sum(e.outcome == "denied" and e.event_type in RESOURCE_EVENT_TYPES for e in ordered)),
    }


def vectorize(features: dict[str, float]) -> list[float]:
    return [float(features[name]) for name in FEATURE_NAMES]
