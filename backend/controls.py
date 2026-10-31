"""Lookups for active response controls (blocked IPs, isolated systems). Used wherever access is decided."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models import ResponseControl


def is_ip_blocked(db: Session, ip: str) -> bool:
    return db.scalar(select(ResponseControl.id).where(
        ResponseControl.kind == "blocked_ip", ResponseControl.value == ip, ResponseControl.active.is_(True)).limit(1)) is not None


def is_isolated(db: Session, resource: str | None) -> bool:
    return bool(resource) and db.scalar(select(ResponseControl.id).where(
        ResponseControl.kind == "isolated_system", ResponseControl.value == resource,
        ResponseControl.active.is_(True)).limit(1)) is not None


def active_controls(db: Session) -> list[ResponseControl]:
    return list(db.scalars(select(ResponseControl).where(ResponseControl.active.is_(True)).order_by(ResponseControl.id.desc())))
