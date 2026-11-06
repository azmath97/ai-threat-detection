"""Authorization of bulk exports and downloads, decided on the server before anything is processed.

`authorize` is called by every real export or download path (`event_service.access_resource`, which serves the resource-access
API and the telemetry endpoint, the payroll export and the document download). It returns one of:

    allow              the normal case: nothing is stored beyond the usual event
    approval_required  more records than EXPORT_APPROVAL_THRESHOLD in one request: a pending ExportRequest is created and a
                       security administrator must approve it; the approval is single-use, bound to this account, resource,
                       action and size, and expires
    over_hard_limit    more than EXPORT_HARD_LIMIT in one request: refused, approval cannot lift it
    hourly_limit       the account would exceed its rolling hourly allowance: refused until older exports age out

Large is not the same as malicious. Staff with write access in the resource's own department (a payroll specialist and payroll
records) get EXPORT_OWNER_MULTIPLIER times the hourly allowance, and an approved request bypasses the hourly allowance (but never
the hard limit). Repeated refused or pending requests by one account become an incident (auth_detection.evaluate_export).
Simulation traffic is flagged synthetic by its caller and never reaches this module. Nothing here contacts another system.
"""
import logging
from dataclasses import dataclass
from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from backend import auth_response
from backend.auth_policy import get_policy
from backend.catalog import RESOURCES
from backend.database import utcnow
from backend.models import AccessPermission, Employee, ExportRequest, SecurityEvent

log = logging.getLogger("auth_defense")
EXPORT_EVENT_TYPES = ("file_download", "data_export")
DECISION_WINDOW_HOURS = 24            # a pending request that nobody decides expires after this long


@dataclass
class Decision:
    outcome: str                      # allow | approval_required | over_hard_limit | hourly_limit
    message: str = ""
    request: ExportRequest | None = None
    retry_after: int | None = None
    approval_id: int | None = None    # the approval consumed by an allowed request

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"

    @property
    def reason(self) -> str:
        return {"approval_required": "export_requires_approval", "over_hard_limit": "export_over_hard_limit",
                "hourly_limit": "export_hourly_limit"}.get(self.outcome, "")


def expire_stale(db: Session) -> int:
    """Close requests and approvals whose time has run out."""
    now = utcnow()
    return db.execute(update(ExportRequest).where(ExportRequest.status.in_(("pending", "approved")), ExportRequest.expires_at.is_not(None),
                                                  ExportRequest.expires_at <= now).values(status="expired")).rowcount or 0


def exported_last_hour(db: Session, employee_id: int) -> tuple[int, object | None]:
    """Records this account has taken in the last hour (real events only) and the time of the oldest one still counted."""
    since = utcnow() - timedelta(hours=1)
    where = (SecurityEvent.employee_id == employee_id, SecurityEvent.event_type.in_(EXPORT_EVENT_TYPES),
             SecurityEvent.outcome == "success", SecurityEvent.is_synthetic.is_(False), SecurityEvent.timestamp >= since)
    total = db.scalar(select(func.coalesce(func.sum(SecurityEvent.records_downloaded), 0)).where(*where)) or 0
    oldest = db.scalar(select(func.min(SecurityEvent.timestamp)).where(*where))
    return int(total), oldest


def hourly_limit(db: Session, employee: Employee, resource: str) -> tuple[int, bool]:
    """The account's hourly allowance for this resource and whether the owner multiplier applied."""
    policy = get_policy()
    permission = db.scalar(select(AccessPermission).where(AccessPermission.employee_id == employee.id, AccessPermission.resource == resource))
    owner = permission is not None and permission.access_level == "write" and RESOURCES.get(resource, {}).get("department") == employee.department
    return policy.export_hourly_limit * (policy.export_owner_multiplier if owner else 1), owner


def _claim_approval(db: Session, employee: Employee, resource: str, action: str, records: int, approval_id: int) -> bool:
    """Spend an approval: only an approved, unexpired one that belongs to this account, resource and action and covers this size,
    and only once (compare-and-set, so two simultaneous requests cannot both use it)."""
    now = utcnow()
    spent = db.execute(update(ExportRequest).where(
        ExportRequest.id == approval_id, ExportRequest.employee_id == employee.id, ExportRequest.status == "approved",
        ExportRequest.resource == resource, ExportRequest.action == action, ExportRequest.records >= records,
        ExportRequest.expires_at.is_not(None), ExportRequest.expires_at > now).values(status="used", used_at=now)).rowcount
    return bool(spent)


def _open(db: Session, employee: Employee, resource: str, action: str, records: int, ip: str, status_: str, reason: str, detail: str,
          expires=None) -> ExportRequest:
    request = ExportRequest(employee_id=employee.id, resource=resource, action=action, records=records, status=status_, reason=reason,
                            detail=detail[:300], source_ip=ip[:45], expires_at=expires)
    db.add(request)
    db.flush()
    auth_response.record_export_request(db, request, employee)
    return request


def authorize(db: Session, employee: Employee, resource: str, action: str, records: int, *, ip: str,
              approval_id: int | None = None) -> Decision:
    policy = get_policy()
    if action not in ("download", "export") or records <= 0:
        return Decision("allow")
    expire_stale(db)
    name = RESOURCES.get(resource, {}).get("name", resource)

    if 0 < policy.export_hard_limit < records:
        request = _open(db, employee, resource, action, records, ip, "refused", "over_hard_limit",
                        f"{records:,} records requested; the absolute limit is {policy.export_hard_limit:,}")
        return Decision("over_hard_limit", f"A single request may not take more than {policy.export_hard_limit:,} records of {name} "
                        f"({records:,} requested). No approval can lift this limit.", request)

    if approval_id is not None and _claim_approval(db, employee, resource, action, records, approval_id):
        return Decision("allow", approval_id=approval_id)

    if 0 < policy.export_approval_threshold < records:
        request = _open(db, employee, resource, action, records, ip, "pending", "approval_required",
                        f"{records:,} records requested; approval is needed above {policy.export_approval_threshold:,}",
                        expires=utcnow() + timedelta(hours=DECISION_WINDOW_HOURS))
        stale = " The approval you supplied is not valid for this request (used, expired, for another request or too small)." \
            if approval_id is not None else ""
        return Decision("approval_required", f"Taking {records:,} records of {name} needs approval from the security team. Request "
                        f"#{request.id} was created; once it is approved, repeat this request with approval_id={request.id}.{stale}", request)

    limit, owner = hourly_limit(db, employee, resource)
    if limit > 0:
        taken, oldest = exported_last_hour(db, employee.id)
        if taken + records > limit:
            wait = max(60, int((oldest + timedelta(hours=1) - utcnow()).total_seconds())) if oldest else 60
            request = _open(db, employee, resource, action, records, ip, "refused", "hourly_limit",
                            f"{taken:,} already taken this hour + {records:,} requested exceeds {limit:,}" + (" (owner allowance)" if owner else ""))
            return Decision("hourly_limit", f"Export limit reached: {taken:,} of {limit:,} records already taken in the last hour; "
                            f"{records:,} more would exceed it. Try again later.", request, retry_after=wait)
    return Decision("allow")


def http_error(decision: Decision) -> HTTPException:
    """The HTTP refusal for a non-allow decision (409 approval needed, 403 absolute limit, 429 hourly limit)."""
    code = {"approval_required": status.HTTP_409_CONFLICT, "over_hard_limit": status.HTTP_403_FORBIDDEN,
            "hourly_limit": status.HTTP_429_TOO_MANY_REQUESTS}[decision.outcome]
    headers = {"Retry-After": str(decision.retry_after)} if decision.retry_after else None
    return HTTPException(code, decision.message, headers=headers)
