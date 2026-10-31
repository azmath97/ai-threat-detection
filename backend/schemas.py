import ipaddress
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer, model_validator

from backend.catalog import EVENT_TYPES, RESOURCE_EVENT_TYPES, RESOURCES
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


def _validate_ip(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("must be a valid IPv4 or IPv6 address") from exc


# ----- requests -----
class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    source_ip: str | None = Field(default=None, description="Simulation only: IP to attribute the login to")

    _ip = field_validator("source_ip")(_validate_ip)

    @field_validator("username")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class ResourceAccessRequest(BaseModel):
    action: Literal["view", "download", "export"] = "view"
    record_count: int = Field(default=0, ge=0, le=10_000_000)
    source_ip: str | None = None

    _ip = field_validator("source_ip")(_validate_ip)


class EventCreate(BaseModel):
    employee_id: int | None = Field(default=None, gt=0, description="Admins only: log on behalf of another employee")
    event_type: str
    resource: str | None = None
    record_count: int = Field(default=0, ge=0, le=10_000_000)
    source_ip: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    _ip = field_validator("source_ip")(_validate_ip)

    @field_validator("event_type")
    @classmethod
    def _event_type(cls, v: str) -> str:
        if v not in EVENT_TYPES:
            raise ValueError(f"must be one of: {', '.join(EVENT_TYPES)}")
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
    id: int
    event_type: str
    resource: str | None
    outcome: str
    source_ip: str
    details: dict[str, Any]
    timestamp: datetime


class EventOut(EventPublic):
    employee_id: int
    employee_username: str
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


class AssessmentOut(APIModel):
    id: int
    employee_id: int
    event_id: int | None
    score: int
    level: str
    factors: list[dict[str, Any]]
    created_at: datetime


class RiskDetailOut(BaseModel):
    employee_id: int
    username: str
    score: int
    level: str
    window_minutes: int
    factors: list[dict[str, Any]]
    attack_stages: list[str]
    attack_confidence: float
    history: list[AssessmentOut]


class AlertOut(APIModel):
    id: int
    employee_id: int
    employee_username: str
    event_id: int | None
    investigation_id: int | None
    severity: str
    status: str
    title: str
    description: str
    risk_score: int
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
