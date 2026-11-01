from datetime import datetime

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base, UTCDateTime, utcnow


def employee_code_for(employee_id: int, role: str) -> str:
    return f"SEC-{9000 + employee_id}" if role == "security_admin" else f"EMP-{1000 + employee_id}"


class Employee(Base):
    __tablename__ = "employees"

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_code: Mapped[str | None] = mapped_column(String(16), unique=True, index=True, nullable=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(160), unique=True)
    department: Mapped[str] = mapped_column(String(64), index=True)
    job_role: Mapped[str] = mapped_column(String(96))
    role: Mapped[str] = mapped_column(String(32), default="employee")  # employee | security_admin
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | locked
    password_hash: Mapped[str] = mapped_column(String(255))
    known_ips: Mapped[list] = mapped_column(JSON, default=list)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    permissions: Mapped[list["AccessPermission"]] = relationship(
        back_populates="employee", cascade="all, delete-orphan"
    )


class EmployeeSession(Base):
    __tablename__ = "employee_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45))
    device_info: Mapped[str | None] = mapped_column(String(200), nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    employee: Mapped[Employee] = relationship()


class AccessPermission(Base):
    __tablename__ = "access_permissions"
    __table_args__ = (UniqueConstraint("employee_id", "resource", name="uq_permission_employee_resource"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"), index=True)
    resource: Mapped[str] = mapped_column(String(64))
    access_level: Mapped[str] = mapped_column(String(16))  # read | write
    granted_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    employee: Mapped[Employee] = relationship(back_populates="permissions")


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_employee_time", "employee_id", "timestamp"),
        Index("ix_events_type_time", "event_type", "timestamp"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"))
    session_id: Mapped[int | None] = mapped_column(ForeignKey("employee_sessions.id", ondelete="SET NULL"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(32))
    resource: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")  # success | failure | denied
    source_ip: Mapped[str] = mapped_column(String(45))
    device_info: Mapped[str | None] = mapped_column(String(200), nullable=True)
    records_accessed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    records_downloaded: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    scenario: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_points: Mapped[int] = mapped_column(Integer, default=0)
    risk_flags: Mapped[list] = mapped_column(JSON, default=list)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    employee: Mapped[Employee] = relationship()

    @property
    def employee_username(self) -> str:
        return self.employee.username


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    __table_args__ = (Index("ix_risk_employee_time", "employee_id", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"))
    event_id: Mapped[int | None] = mapped_column(ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True)
    score: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String(16))  # normal | suspicious | high_risk | critical
    factors: Mapped[list] = mapped_column(JSON, default=list)
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    stage: Mapped[str | None] = mapped_column(String(32), nullable=True)
    components: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    exposure: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AttackInvestigation(Base):
    __tablename__ = "attack_investigations"

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open | contained | resolved
    attack_stage: Mapped[str] = mapped_column(String(32), default="none")
    attack_type: Mapped[str] = mapped_column(String(48), default="none", server_default="none")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    indicators: Mapped[list] = mapped_column(JSON, default=list)
    recommended_actions: Mapped[list] = mapped_column(JSON, default=list)
    exposure: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    first_event_id: Mapped[int | None] = mapped_column(Integer, nullable=True)   # first suspicious event
    latest_event_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # latest suspicious event
    case_file: Mapped[dict | None] = mapped_column(JSON, nullable=True)          # sessions, IPs, resources, exposure totals
    explanation: Mapped[dict | None] = mapped_column(JSON, nullable=True)        # deterministic, evidence-based
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)  # when it was resolved

    employee: Mapped[Employee] = relationship()

    @property
    def employee_username(self) -> str:
        return self.employee.username


class InvestigationEvidence(Base):
    """Append-only copy of an event as it was when it was collected into an investigation.

    The snapshot and its SHA-256 are never rewritten; only `relations` (why the event is related) may change.
    Exports compare the snapshot to the live event so tampering with the original event is detectable.
    """

    __tablename__ = "investigation_evidence"
    __table_args__ = (UniqueConstraint("investigation_id", "event_id", name="uq_evidence_investigation_event"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("attack_investigations.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[int] = mapped_column(Integer, index=True)
    snapshot: Mapped[dict] = mapped_column(JSON)
    content_hash: Mapped[str] = mapped_column(String(64))
    relations: Mapped[list] = mapped_column(JSON, default=list)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    __table_args__ = (Index("ix_alerts_status_severity", "status", "severity"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True)
    assessment_id: Mapped[int | None] = mapped_column(ForeignKey("risk_assessments.id", ondelete="SET NULL"), nullable=True)
    investigation_id: Mapped[int | None] = mapped_column(ForeignKey("attack_investigations.id", ondelete="SET NULL"), nullable=True)
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | investigating | contained | resolved | false_positive
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    attack_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    stage: Mapped[str | None] = mapped_column(String(32), nullable=True)
    first_event_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[list | None] = mapped_column(JSON, nullable=True)
    exposure: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    recommended_actions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    detected_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    employee: Mapped[Employee] = relationship()

    @property
    def employee_username(self) -> str:
        return self.employee.username


class ContainmentAction(Base):
    __tablename__ = "containment_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int | None] = mapped_column(ForeignKey("attack_investigations.id", ondelete="SET NULL"), nullable=True, index=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"), index=True)
    action_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="completed")
    reason: Mapped[str] = mapped_column(String(500))
    performed_by: Mapped[int] = mapped_column(ForeignKey("employees.id"))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class ResponseControl(Base):
    """An active containment control enforced by the backend: a blocked source IP or an isolated system."""

    __tablename__ = "response_controls"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)  # blocked_ip | isolated_system
    value: Mapped[str] = mapped_column(String(64), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    reason: Mapped[str] = mapped_column(String(500), default="")
    created_by: Mapped[int] = mapped_column(ForeignKey("employees.id"))
    action_id: Mapped[int | None] = mapped_column(ForeignKey("containment_actions.id", ondelete="SET NULL"), nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    released_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
