"""Lookups for active response controls (blocked IPs, isolated systems). Used wherever access is decided."""
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.database import utcnow
from backend.models import IpBlock, ResponseControl


def is_ip_blocked(db: Session, ip: str) -> bool:
    """True for an address blocked by an analyst's containment action or by an active (unexpired) authentication-defence block."""
    if db.scalar(select(ResponseControl.id).where(
            ResponseControl.kind == "blocked_ip", ResponseControl.value == ip, ResponseControl.active.is_(True)).limit(1)) is not None:
        return True
    return db.scalar(select(IpBlock.id).where(
        IpBlock.ip == ip, IpBlock.active.is_(True), or_(IpBlock.expires_at.is_(None), IpBlock.expires_at > utcnow())).limit(1)) is not None


def is_isolated(db: Session, resource: str | None) -> bool:
    return bool(resource) and db.scalar(select(ResponseControl.id).where(
        ResponseControl.kind == "isolated_system", ResponseControl.value == resource,
        ResponseControl.active.is_(True)).limit(1)) is not None


def active_controls(db: Session) -> list[ResponseControl]:
    return list(db.scalars(select(ResponseControl).where(ResponseControl.active.is_(True)).order_by(ResponseControl.id.desc())))
