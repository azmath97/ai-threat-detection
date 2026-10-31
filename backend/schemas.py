import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer, model_validator

from backend.catalog import CLIENT_EVENT_TYPES, RESOURCE_EVENT_TYPES, RESOURCES
from backend.config import to_local
from backend.response_service import ACTION_TYPES


class APIModel(BaseModel):
    """Adds a `<field>_local` ISO string next to every datetime field (display timezone)."""

    model_config = ConfigDict(from_attributes=True)

    @model_serializer(mode="wrap")
    def _add_local_times(self, handler):
        data = handler(self)
        for name in type(self).model_fields:
            value = getattr(self, name, None)
            if isinstance(value, datetime):
                data[f"{name}_local"] = to_local(value).isoformat()
        return data


# ----- requests -----
class LoginRequest(BaseModel):
    employee_id: str | None = Field(default=None, min_length=3, max_length=64, description="e.g. EMP-1001")
    username: str | None = Field(default=None, min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def _one_identifier(self):
        if not (self.employee_id or self.username):
            raise ValueError("employee_id is required")
        return self

    @property
    def identifier(self) -> str:
        return (self.employee_id or self.username or "").strip()


class ResourceAccessRequest(BaseModel):
    action: Literal["view", "download", "export"] = "view"
    record_count: int = Field(default=0, ge=0, le=10_000_000)


class EventCreate(BaseModel):
    """Client telemetry for the authenticated employee. Identity, IP and device are set by the backend."""

    event_type: str
    resource: str | None = None
    record_count: int = Field(default=0, ge=0, le=10_000_000)
    details: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = Field(default=None, max_length=64, description="Idempotency key: a replay is stored once")

    @field_validator("event_type")
    @classmethod
    def _event_type(cls, v: str) -> str:
        if v not in CLIENT_EVENT_TYPES:
            raise ValueError(f"must be one of: {', '.join(CLIENT_EVENT_TYPES)}")
        return v

    @field_validator("details")
    @classmethod
    def _details_size(cls, v: dict) -> dict:
        if len(json.dumps(v, default=str)) > 4000:
            raise ValueError("details too large (max 4000 characters)")
        return v

    @model_validator(mode="after")
    def _resource_rules(self):
        if self.event_type in RESOURCE_EVENT_TYPES and not self.resource:
            raise ValueError("resource is required for resource events")
        if self.resource and self.resource not in RESOURCES:
            raise ValueError(f"unknown resource '{self.resource}'")
        return self


class RiskAssessRequest(BaseModel):
    employee_id: int = Field(gt=0)


class AlertUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"]


class InvestigationCreate(BaseModel):
    employee_id: int = Field(gt=0)


class InvestigationUpdate(BaseModel):
    status: Literal["open", "closed"]


class ContainmentRequest(BaseModel):
    employee_id: int = Field(gt=0)
    action_type: str
    reason: str = Field(min_length=3, max_length=500)
    investigation_id: int | None = Field(default=None, gt=0)

    @field_validator("action_type")
    @classmethod
    def _action(cls, v: str) -> str:
        if v not in ACTION_TYPES:
            raise ValueError(f"must be one of: {', '.join(ACTION_TYPES)}")
        return v


# ----- responses -----
class EmployeeOut(APIModel):
    id: int
    employee_code: str | None
    username: str
    full_name: str
    email: str
    department: str
    job_role: str
    role: str
    status: str
    created_at: datetime
    last_login_at: datetime | None


class PermissionOut(BaseModel):
    resource: str
    name: str
    sensitivity: str
    access_level: str


class ProfileOut(EmployeeOut):
    known_ips: list[str]
    permissions: list[PermissionOut]
    previous_login_at: datetime | None = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    employee: EmployeeOut


class ResourceOut(BaseModel):
    id: str
    name: str
    sensitivity: str
    department: str
    access_level: str | None


class ResourceAccessOut(BaseModel):
    resource: str
    action: str
    record_count: int
    records: list[dict[str, Any]]
    event_id: int
    timestamp: datetime


class EventPublic(APIModel):
    """What an employee may see about an event: no source/device internals, metadata or risk data."""

    id: int
    event_type: str
    resource: str | None
    outcome: str
    records_accessed: int
    records_downloaded: int
    timestamp: datetime


class EventOut(EventPublic):
    employee_id: int
    employee_username: str
    session_id: int | None
    source_ip: str
    device_info: str | None
    details: dict[str, Any]
    is_synthetic: bool
    scenario: str | None
    risk_points: int
    risk_flags: list[dict[str, Any]]


class EventPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[EventOut]


class EventCreated(BaseModel):
    event: EventPublic
    risk_score: int | None = None
    risk_level: str | None = None
    alert_id: int | None = None
    duplicate: bool = False


class RiskFactorOut(BaseModel):
    rule: str
    points: int
    count: int | None = None
    description: str


class EmployeeRiskOut(BaseModel):
    employee_id: int
    username: str
    full_name: str
    department: str
    status: str
    score: int
    level: str
    current_stage: str = "none"
    stage_label: str = "None"
    data_exposure: str = "none"


class AssessmentOut(APIModel):
    id: int
    employee_id: int
    event_id: int | None
    score: int
    level: str
    factors: list[dict[str, Any]]
    ml_score: float | None = None
    stage: str | None = None
    components: dict[str, Any] | None = None
    exposure: dict[str, Any] | None = None
    created_at: datetime


class RiskDetailOut(BaseModel):
    employee_id: int
    username: str
    score: int
    confidence: float
    level: str
    window_minutes: int
    factors: list[dict[str, Any]]
    attack_stages: list[str]
    attack_confidence: float
    current_stage: str
    stage_label: str
    stage_history: list[str]
    independent_stages: int
    components: dict[str, Any]
    ml: dict[str, Any] | None
    features: dict[str, Any]
    exposure: dict[str, Any]
    evidence: list[dict[str, Any]]
    links: dict[str, Any]
    first_event_id: int | None
    recommended_actions: list[dict[str, Any]]
    history: list[AssessmentOut]


class AlertOut(APIModel):
    id: int
    employee_id: int
    employee_username: str
    event_id: int | None          # the triggering event
    first_event_id: int | None    # first suspicious event in the correlated chain
    investigation_id: int | None
    severity: str
    status: str
    title: str
    description: str
    risk_score: int
    attack_confidence: float
    stage: str | None
    evidence: list[dict[str, Any]] | None
    exposure: dict[str, Any] | None
    recommended_actions: list[dict[str, Any]] | None
    detected_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ContainmentOut(APIModel):
    id: int
    investigation_id: int | None
    employee_id: int
    action_type: str
    status: str
    reason: str
    performed_by: int
    details: dict[str, Any]
    created_at: datetime


class InvestigationOut(APIModel):
    id: int
    employee_id: int
    employee_username: str
    status: str
    attack_stage: str
    confidence: float
    risk_score: int
    summary: str
    timeline: list[dict[str, Any]]
    indicators: list[str]
    recommended_actions: list[dict[str, Any]]
    exposure: dict[str, Any] | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


class InvestigationDetail(InvestigationOut):
    containment_actions: list[ContainmentOut]


class DashboardStats(BaseModel):
    generated_at: datetime
    total_employees: int
    active_sessions: int
    events_total: int
    events_24h: int
    open_alerts: int
    alerts_by_severity: dict[str, int]
    open_investigations: int
    high_risk_employees: int
    average_risk_score: float
    containment_actions_total: int
    locked_accounts: int
    events_by_type_24h: dict[str, int]
    events_per_hour_24h: list[dict[str, Any]]
    top_risk_employees: list[EmployeeRiskOut]
