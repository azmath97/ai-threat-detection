from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.catalog import SEVERITY_LEVELS
from backend.database import Base, UTCDateTime, utcnow

# Allowed values, kept next to the constraints that enforce them so the database refuses anything else.
ALERT_STATUSES = ("open", "investigating", "contained", "resolved", "false_positive")
INVESTIGATION_STATUSES = ("open", "contained", "resolved")
RUN_STATUSES = ("queued", "running", "completed", "failed", "cancelled")


def _in(column: str, values) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _partial(condition: str) -> dict:
    """Partial-index predicate understood by both SQLite and PostgreSQL."""
    return {"sqlite_where": text(condition), "postgresql_where": text(condition)}


def employee_code_for(employee_id: int, role: str) -> str:
    return f"SEC-{9000 + employee_id}" if role == "security_admin" else f"EMP-{1000 + employee_id}"


class Employee(Base):
    __tablename__ = "employees"
    __table_args__ = (
        CheckConstraint(_in("status", ("active", "locked")), name="ck_employees_status"),
        CheckConstraint(_in("role", ("employee", "security_admin")), name="ck_employees_role"),
    )

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
    __table_args__ = (Index("ix_sessions_ip", "ip_address"),)     # "revoke the sessions of a blocked address"

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
    __table_args__ = (
        UniqueConstraint("employee_id", "resource", name="uq_permission_employee_resource"),
        CheckConstraint(_in("access_level", ("read", "write")), name="ck_permissions_access_level"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"), index=True)
    resource: Mapped[str] = mapped_column(String(64))
    access_level: Mapped[str] = mapped_column(String(16))  # read | write
    granted_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    employee: Mapped[Employee] = relationship(back_populates="permissions")


class SecurityEvent(Base):
    """One recorded action. Event ingestion is idempotent on (employee_id, request_id): a client that retries or re-renders
    with the same request_id gets the original event back instead of a duplicate (enforced by a partial unique index)."""

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_employee_time", "employee_id", "timestamp"),       # per-employee windows, baselines, correlation
        Index("ix_events_type_time", "event_type", "timestamp"),
        Index("ix_events_timestamp", "timestamp"),                          # "last 24 h" counts and the hourly chart
        Index("ix_events_source_ip_time", "source_ip", "timestamp"),        # investigation evidence by address
        Index("ix_events_session", "session_id"),                           # investigation evidence by session
        Index("uq_events_employee_request", "employee_id", "request_id", unique=True, **_partial("request_id IS NOT NULL")),
        CheckConstraint(_in("outcome", ("success", "failure", "denied")), name="ck_events_outcome"),
        CheckConstraint("records_accessed >= 0 AND records_downloaded >= 0", name="ck_events_records_nonnegative"),
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
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    simulation_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("simulation_runs.id", ondelete="SET NULL"), nullable=True, index=True)
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
    __table_args__ = (
        Index("ix_risk_employee_time", "employee_id", "created_at"),
        Index("ix_risk_event", "event_id"),                                  # "latest assessment of each event"
        CheckConstraint(_in("level", SEVERITY_LEVELS), name="ck_risk_level"),
        CheckConstraint("score >= 0 AND score <= 100", name="ck_risk_score_range"),
    )

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
    """At most one *active* (open or contained) investigation per employee, enforced by a partial unique index."""

    __tablename__ = "attack_investigations"
    __table_args__ = (
        Index("ix_inv_employee_status", "employee_id", "status"),
        Index("ix_inv_updated", "updated_at"),                               # change token and "latest first" lists
        Index("uq_inv_one_active_per_employee", "employee_id", unique=True, **_partial("status IN ('open', 'contained')")),
        CheckConstraint(_in("status", INVESTIGATION_STATUSES), name="ck_investigations_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"))   # indexed by ix_inv_employee_status
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
    simulation_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("simulation_runs.id", ondelete="SET NULL"), nullable=True, index=True)
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
    """At most one *open or investigating* alert per employee, enforced by a partial unique index."""

    __tablename__ = "security_alerts"
    __table_args__ = (
        Index("ix_alerts_status_severity", "status", "severity"),
        Index("ix_alerts_employee_status", "employee_id", "status"),
        Index("ix_alerts_investigation", "investigation_id"),
        Index("ix_alerts_updated", "updated_at"),
        Index("uq_alerts_one_open_per_employee", "employee_id", unique=True, **_partial("status IN ('open', 'investigating')")),
        CheckConstraint(_in("status", ALERT_STATUSES), name="ck_alerts_status"),
        CheckConstraint(_in("severity", SEVERITY_LEVELS), name="ck_alerts_severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"))   # indexed by ix_alerts_employee_status
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
    """An auditable simulated containment action. It records what was requested, by whom, for which alert or investigation,
    what it did to this application's own records, and that no external system was involved."""

    __tablename__ = "containment_actions"
    __table_args__ = (
        Index("uq_containment_idempotency_key", "idempotency_key", unique=True),      # NULLs are distinct on SQLite and PostgreSQL
        Index("ix_containment_employee_time", "employee_id", "created_at"),
        CheckConstraint(_in("status", ("completed", "failed")), name="ck_containment_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int | None] = mapped_column(ForeignKey("attack_investigations.id", ondelete="SET NULL"), nullable=True, index=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("security_alerts.id", ondelete="SET NULL"), nullable=True, index=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"))   # indexed by ix_containment_employee_time
    action_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="completed")
    reason: Mapped[str] = mapped_column(String(500))
    performed_by: Mapped[int] = mapped_column(ForeignKey("employees.id"))
    idempotency_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)

    performer: Mapped[Employee] = relationship(foreign_keys=[performed_by])

    @property
    def simulated(self) -> bool:
        return True

    @property
    def scope(self) -> str | None:
        return (self.details or {}).get("scope")

    @property
    def result(self) -> str | None:
        return (self.details or {}).get("result")

    @property
    def effects(self) -> list[str]:
        return list((self.details or {}).get("effects", []))

    @property
    def external_systems_contacted(self) -> list[str]:
        return list((self.details or {}).get("external_systems_contacted", []))

    @property
    def performed_by_username(self) -> str:
        return self.performer.username

    @property
    def status_label(self) -> str:
        return "Simulation completed" if self.status == "completed" else self.status


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


class SimulationRun(Base):
    """One simulated scenario run: its seed, parameters, generated plan, progress and outcome.

    `active_slot` is 1 while the run is queued or running and NULL afterwards; its unique index lets the database
    itself guarantee that at most one run is active at a time.
    """

    __tablename__ = "simulation_runs"
    __table_args__ = (
        Index("uq_runs_idempotency_key", "idempotency_key", unique=True),
        Index("uq_runs_active_slot", "active_slot", unique=True),
        Index("ix_runs_created", "created_at"),
        CheckConstraint(_in("status", RUN_STATUSES), name="ck_runs_status"),
        CheckConstraint(_in("seed_mode", ("fixed", "random")), name="ck_runs_seed_mode"),
        CheckConstraint("steps_done >= 0 AND steps_total >= 0", name="ck_runs_steps_nonnegative"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scenario: Mapped[str] = mapped_column(String(64), index=True)
    seed: Mapped[int] = mapped_column(Integer)
    seed_mode: Mapped[str] = mapped_column(String(8))                      # fixed | random
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)  # queued|running|completed|failed|cancelled
    active_slot: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target_employee_id: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True)
    started_by_id: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    pace: Mapped[str] = mapped_column(String(8), default="demo")
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    plan: Mapped[dict] = mapped_column(JSON, default=dict)
    plan_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    steps_total: Mapped[int] = mapped_column(Integer, default=0)
    steps_done: Mapped[int] = mapped_column(Integer, default=0)
    results: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    target: Mapped[Employee | None] = relationship(foreign_keys=[target_employee_id])


class ResponseControl(Base):
    """An active containment control enforced by the backend: a blocked source IP or an isolated system."""

    __tablename__ = "response_controls"
    __table_args__ = (
        # one active block per address / isolation per system, even when two administrators act at the same moment
        Index("uq_controls_one_active", "kind", "value", unique=True, **_partial("active")),
        CheckConstraint(_in("kind", ("blocked_ip", "isolated_system")), name="ck_controls_kind"),
    )

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
