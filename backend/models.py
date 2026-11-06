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
    # Why and by whom the account is locked. `locked_by` is "policy:<name>" for an automatic lock (which expires at
    # `lock_expires_at`) or the analyst's employee ID for a manual one (which never expires by itself).
    lock_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    locked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    lock_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    locked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

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
    impact_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)      # impact of the evidence, not of the score
    evidence_strength: Mapped[str | None] = mapped_column(String(16), nullable=True)    # qualitative corroboration, not a probability
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
    risk_score_exact: Mapped[float] = mapped_column(Float, default=0.0)         # heuristic risk score, 0-100 (not a probability)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    impact_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    evidence_strength: Mapped[str | None] = mapped_column(String(16), nullable=True)
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
    severity: Mapped[str] = mapped_column(String(16))   # the risk band when the alert was raised (see `risk_band`); impact is `impact_severity`
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | investigating | contained | resolved | false_positive
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    peak_risk_score: Mapped[float] = mapped_column(Float, default=0.0)  # highest heuristic risk score (0-100) seen; not a probability
    impact_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    evidence_strength: Mapped[str | None] = mapped_column(String(16), nullable=True)
    score_basis: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # how the score was built when the alert was raised or last raised
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
    def risk_band(self) -> str:
        return self.severity

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


# ------------------------------------------------------------------------------------------ authentication defence
AUTH_OUTCOMES = ("success", "failure", "denied")
INCIDENT_KINDS = ("account_brute_force", "credential_stuffing", "ip_failure_burst", "distributed_account_attack",
                  "login_after_failures", "repeated_forbidden_access", "idor_probe", "unauthenticated_flood", "bulk_export_attempt")
INCIDENT_STATUSES = ("open", "investigating", "contained", "resolved", "false_positive")
ACTION_TYPES = ("lock_account", "unlock_account", "revoke_sessions", "block_ip", "unblock_ip")
ACTION_STATUSES = ("completed", "failed", "skipped", "pending_approval")


class AuthAttempt(Base):
    """One real sign-in attempt that reached the backend (never a password or token).

    `subject` is the employee ID when the identifier belongs to an account, otherwise "unknown:" plus a keyed hash of what
    was typed, so credential stuffing across unknown names can be counted without storing a mistyped password."""

    __tablename__ = "auth_attempts"
    __table_args__ = (
        Index("ix_auth_attempts_ip_time", "source_ip", "timestamp"),
        Index("ix_auth_attempts_subject_time", "subject", "timestamp"),
        Index("ix_auth_attempts_employee_time", "employee_id", "timestamp"),
        Index("ix_auth_attempts_time", "timestamp"),
        CheckConstraint(_in("outcome", AUTH_OUTCOMES), name="ck_auth_attempts_outcome"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    source_ip: Mapped[str] = mapped_column(String(45))
    subject: Mapped[str] = mapped_column(String(40))
    employee_id: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True)
    outcome: Mapped[str] = mapped_column(String(12))   # success | failure (wrong credentials) | denied (blocked or locked)
    reason: Mapped[str] = mapped_column(String(32))    # ok | bad_password | unknown_identifier | account_locked | ip_blocked
    device_info: Mapped[str | None] = mapped_column(String(200), nullable=True)


class AccessDenial(Base):
    """A real API request the backend refused with 401 or 403 (never the request body, the token or any credential).

    `route` is the route template (for example /api/employees/{employee_id}) and `object_ref` the identifier that was asked for,
    so probing many different records through one route (IDOR) can be told apart from repeating one forbidden call."""

    __tablename__ = "access_denials"
    __table_args__ = (
        Index("ix_denials_employee_time", "employee_id", "timestamp"),
        Index("ix_denials_ip_time", "source_ip", "timestamp"),
        Index("ix_denials_time", "timestamp"),
        CheckConstraint("status_code IN (401, 403)", name="ck_denials_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    source_ip: Mapped[str] = mapped_column(String(45))
    employee_id: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True)
    method: Mapped[str] = mapped_column(String(8))
    route: Mapped[str] = mapped_column(String(120))
    object_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status_code: Mapped[int] = mapped_column(Integer)


class AuthIncident(Base):
    """A detected authentication attack. At most one open, investigating or contained incident per kind and subject."""

    __tablename__ = "auth_incidents"
    __table_args__ = (
        Index("uq_auth_incidents_one_active", "dedup_key", unique=True, **_partial("status IN ('open', 'investigating', 'contained')")),
        Index("ix_auth_incidents_status_severity", "status", "severity"),
        Index("ix_auth_incidents_ip", "source_ip"),
        Index("ix_auth_incidents_employee", "employee_id"),
        Index("ix_auth_incidents_updated", "updated_at"),
        CheckConstraint(_in("status", INCIDENT_STATUSES), name="ck_auth_incidents_status"),
        CheckConstraint(_in("severity", SEVERITY_LEVELS), name="ck_auth_incidents_severity"),
        CheckConstraint(_in("kind", INCIDENT_KINDS), name="ck_auth_incidents_kind"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))     # a rule-based band for this pattern, not a probability
    status: Mapped[str] = mapped_column(String(16), default="open")
    dedup_key: Mapped[str] = mapped_column(String(120))
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    employee_id: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(200))
    explanation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)   # counts, window, thresholds and the attempt ids behind them
    attempts_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    resolution_note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    employee: Mapped[Employee | None] = relationship()
    actions: Mapped[list["ResponseAction"]] = relationship(back_populates="incident", order_by="ResponseAction.id")


class ResponseAction(Base):
    """What the response engine or an analyst did about an incident, and the result. Enforcement happens inside this
    application (account status, sessions, application-level IP blocks); no external system is contacted."""

    __tablename__ = "auth_response_actions"
    __table_args__ = (
        Index("uq_auth_actions_idempotency_key", "idempotency_key", unique=True),
        Index("ix_auth_actions_incident", "incident_id"),
        Index("ix_auth_actions_target_time", "target", "created_at"),
        CheckConstraint(_in("action_type", ACTION_TYPES), name="ck_auth_actions_type"),
        CheckConstraint(_in("status", ACTION_STATUSES), name="ck_auth_actions_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("auth_incidents.id", ondelete="SET NULL"), nullable=True)
    employee_id: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True)
    target: Mapped[str] = mapped_column(String(64))          # employee ID or IP address
    action_type: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(20))
    automatic: Mapped[bool] = mapped_column(Boolean, default=False)
    policy: Mapped[str | None] = mapped_column(String(64), nullable=True)
    performed_by: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True)
    reason: Mapped[str] = mapped_column(String(500), default="")
    result: Mapped[str] = mapped_column(String(300), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    idempotency_key: Mapped[str | None] = mapped_column(String(96), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)

    incident: Mapped[AuthIncident | None] = relationship(back_populates="actions")
    performer: Mapped[Employee | None] = relationship(foreign_keys=[performed_by])


EXPORT_STATUSES = ("pending", "approved", "denied", "used", "expired", "refused")


class ExportRequest(Base):
    """A download or export the backend did not simply allow: it needs a security administrator's approval (pending, then
    approved or denied), or it was refused outright (above the absolute cap or the rolling hourly limit). An approval is
    single-use, bound to one account, resource, action and size, and expires. Allowed exports leave only their normal event."""

    __tablename__ = "export_requests"
    __table_args__ = (
        Index("ix_export_requests_employee_time", "employee_id", "created_at"),
        Index("ix_export_requests_status", "status"),
        CheckConstraint(_in("status", EXPORT_STATUSES), name="ck_export_requests_status"),
        CheckConstraint(_in("action", ("download", "export")), name="ck_export_requests_action"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"))
    resource: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(16))
    records: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(12), default="pending")
    reason: Mapped[str] = mapped_column(String(32))          # approval_required | over_hard_limit | hourly_limit
    detail: Mapped[str] = mapped_column(String(300), default="")
    source_ip: Mapped[str] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)   # decision deadline, then the approval's validity
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    decision_note: Mapped[str | None] = mapped_column(String(300), nullable=True)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    employee: Mapped[Employee] = relationship(foreign_keys=[employee_id])
    decider: Mapped[Employee | None] = relationship(foreign_keys=[decided_by])


class IpBlock(Base):
    """An application-level block: this backend refuses sign-ins and API calls from the address. It is not a firewall rule
    and does not stop traffic reaching the host."""

    __tablename__ = "ip_blocks"
    __table_args__ = (
        Index("uq_ip_blocks_one_active", "ip", unique=True, **_partial("active")),
        Index("ix_ip_blocks_active_expiry", "active", "expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(16), default="policy")        # policy | analyst
    reason: Mapped[str] = mapped_column(String(500), default="")
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("auth_incidents.id", ondelete="SET NULL"), nullable=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    released_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    released_by: Mapped[int | None] = mapped_column(ForeignKey("employees.id", ondelete="SET NULL"), nullable=True)
    release_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
