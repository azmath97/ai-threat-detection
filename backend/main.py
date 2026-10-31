import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend import (
    correlation_engine,
    detection_engine,
    event_service,
    investigation_service,
    portal_routes,
    response_service,
    simulation_routes,
)
from backend.auth_service import authenticate, find_employee
from backend.catalog import (
    EVENT_TO_ACTION,
    EVENT_TYPES,
    RESOURCE_EVENT_TYPES,
    RESOURCES,
    SENSITIVITY_LABELS,
    is_self_service,
)
from backend.config import get_settings
from backend.database import SessionLocal, get_db, init_db, utcnow
from backend.errors import ServiceError
from backend.event_service import write_audit
from backend.models import (
    AttackInvestigation,
    AuditLog,
    ContainmentAction,
    Employee,
    EmployeeSession,
    RiskAssessment,
    SecurityAlert,
    SecurityEvent,
)
from backend.schemas import (
    AlertOut,
    AlertUpdate,
    AssessmentOut,
    ContainmentOut,
    ContainmentRequest,
    DashboardStats,
    EmployeeOut,
    EmployeeRiskOut,
    EventCreate,
    EventCreated,
    EventOut,
    EventPage,
    EventPublic,
    InvestigationCreate,
    InvestigationDetail,
    InvestigationOut,
    InvestigationUpdate,
    LoginRequest,
    LoginResponse,
    PermissionOut,
    ProfileOut,
    ResourceAccessOut,
    ResourceAccessRequest,
    ResourceOut,
    RiskAssessRequest,
    RiskDetailOut,
)
from backend.security import AuthContext, device_info, get_auth, require_admin, resolve_ip

logger = logging.getLogger("insider_threat")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    if get_settings().auto_seed:
        from data.seed_data import seed_database

        with SessionLocal() as db:
            if seed_database(db):
                logger.info("Seeded synthetic demo data")
    yield


app = FastAPI(
    title="AI-Based Insider Threat Detection API",
    description="Single source of truth for the Employee Portal and SOC Dashboard (synthetic data only).",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(portal_routes.router)
app.include_router(simulation_routes.router)


@app.exception_handler(ServiceError)
async def service_error_handler(_request: Request, exc: ServiceError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


def _get_employee_or_404(db: Session, employee_id: int) -> Employee:
    employee = db.get(Employee, employee_id)
    if employee is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Employee not found")
    return employee


def _profile(db: Session, employee: Employee, internal: bool = False) -> ProfileOut:
    """`internal` adds security-team-only fields (known IPs); employees never receive them."""
    permissions = [
        PermissionOut(
            resource=p.resource,
            name=RESOURCES[p.resource]["name"],
            sensitivity=SENSITIVITY_LABELS[RESOURCES[p.resource]["sensitivity"]],
            access_level=p.access_level,
        )
        for p in sorted(employee.permissions, key=lambda p: p.resource)
        if p.resource in RESOURCES
    ]
    previous_login = db.scalars(
        select(SecurityEvent.timestamp)
        .where(SecurityEvent.employee_id == employee.id, SecurityEvent.event_type == "login")
        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .offset(1)
        .limit(1)
    ).first()
    base = {name: getattr(employee, name) for name in EmployeeOut.model_fields}
    return ProfileOut(
        **base, known_ips=list(employee.known_ips or []) if internal else [], permissions=permissions,
        previous_login_at=previous_login,
    )


# ---------------------------------------------------------------- health
@app.get("/api/health", tags=["system"])
def health(db: Session = Depends(get_db)):
    db.scalar(select(func.count(Employee.id)))
    return {"status": "ok", "time": utcnow().isoformat(), "display_timezone": get_settings().display_timezone}


# ---------------------------------------------------------------- auth
@app.post("/api/auth/login", response_model=LoginResponse, tags=["auth"])
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = resolve_ip(request, find_employee(db, body.identifier))
    result = authenticate(db, body.identifier, body.password, ip=ip, device_info=device_info(request))
    return LoginResponse(
        access_token=result.token, expires_at=result.session.expires_at,
        employee=EmployeeOut.model_validate(result.employee),
    )


@app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["auth"])
def logout(request: Request, auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)):
    auth.session.revoked_at = utcnow()
    event_service.record_event(db, auth.employee, "logout", source_ip=resolve_ip(request, auth.employee),
                               session=auth.session, device_info=device_info(request), commit=False)
    write_audit(db, "logout", actor_id=auth.employee.id, target_type="session", target_id=auth.session.id)
    db.commit()


# ---------------------------------------------------------------- employees
@app.get("/api/employees/me", response_model=ProfileOut, tags=["employees"])
def my_profile(auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)):
    return _profile(db, auth.employee)


@app.get("/api/employees", response_model=list[EmployeeOut], tags=["employees"])
def list_employees(_: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    return db.scalars(select(Employee).order_by(Employee.id)).all()


@app.get("/api/employees/{employee_id}", response_model=ProfileOut, tags=["employees"])
def get_employee(employee_id: int, auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)):
    if employee_id != auth.employee.id and not auth.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only view your own profile")
    return _profile(db, _get_employee_or_404(db, employee_id), internal=auth.is_admin)


# ---------------------------------------------------------------- resources
@app.get("/api/resources", response_model=list[ResourceOut], tags=["resources"])
def list_resources(auth: AuthContext = Depends(get_auth)):
    levels = {p.resource: p.access_level for p in auth.employee.permissions}
    return [
        ResourceOut(
            id=rid,
            name=meta["name"],
            sensitivity=SENSITIVITY_LABELS[meta["sensitivity"]],
            department=meta["department"],
            access_level="read" if is_self_service(rid) else levels.get(rid),
        )
        for rid, meta in RESOURCES.items()
    ]


@app.post("/api/resources/{resource_id}/access", response_model=ResourceAccessOut, tags=["resources"])
def access_resource(
    resource_id: str,
    body: ResourceAccessRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    meta = RESOURCES.get(resource_id)
    if meta is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    result, permitted = event_service.access_resource(
        db, auth.employee, resource_id, body.action, source_ip=resolve_ip(request, auth.employee),
        session=auth.session, record_count=body.record_count, device_info=device_info(request),
    )
    if not permitted:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"You do not have permission to {body.action} {meta['name']}")
    label = SENSITIVITY_LABELS[meta["sensitivity"]]
    shown = min(body.record_count or 5, 5)
    records = [
        {"record_id": f"{resource_id[:4].upper()}-{i:06d}", "summary": f"Synthetic {meta['name']} record {i}", "classification": label}
        for i in range(1, shown + 1)
    ]
    return ResourceAccessOut(
        resource=resource_id, action=body.action, record_count=body.record_count, records=records,
        event_id=result.event.id, timestamp=result.event.timestamp,
    )


# ---------------------------------------------------------------- events
@app.post("/api/events", response_model=EventCreated, status_code=status.HTTP_201_CREATED, tags=["events"])
def create_event(
    body: EventCreate, request: Request, auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)
):
    """Telemetry for the authenticated employee only; identity, IP and device are derived by the backend."""
    ip, device = resolve_ip(request, auth.employee), device_info(request)
    if body.event_type in RESOURCE_EVENT_TYPES:
        result, _ = event_service.access_resource(
            db, auth.employee, body.resource, EVENT_TO_ACTION[body.event_type], source_ip=ip, session=auth.session,
            record_count=body.record_count, details=body.details, device_info=device,
        )
    else:
        outcome = "denied" if body.event_type == "permission_change_attempt" else "success"
        result = event_service.record_event(
            db, auth.employee, body.event_type, source_ip=ip, resource=body.resource, outcome=outcome,
            details=body.details, session=auth.session, device_info=device,
            records_accessed=body.record_count, records_downloaded=body.record_count if outcome == "success" else 0,
        )

    if auth.is_admin:
        return EventCreated(event=EventPublic.model_validate(result.event), risk_score=result.assessment.score,
                            risk_level=result.assessment.level, alert_id=result.alert.id if result.alert else None)
    return EventCreated(event=EventPublic.model_validate(result.event))


def _parse_ts(raw: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Invalid timestamp '{raw}'")
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@app.get("/api/events", response_model=EventPage, tags=["events"])
def list_events(
    _: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
    employee_id: int | None = Query(None, gt=0),
    event_type: str | None = Query(None),
    outcome: str | None = Query(None, pattern="^(success|failure|denied)$"),
    since: str | None = Query(None, description="ISO-8601 timestamp (UTC if no offset)"),
    until: str | None = Query(None),
    min_risk_points: int = Query(0, ge=0),
    synthetic: bool | None = Query(None, description="Filter simulation-generated events"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    if event_type is not None and event_type not in EVENT_TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"event_type must be one of {', '.join(EVENT_TYPES)}")
    conditions = [SecurityEvent.risk_points >= min_risk_points]
    if synthetic is not None:
        conditions.append(SecurityEvent.is_synthetic.is_(synthetic))
    if employee_id:
        conditions.append(SecurityEvent.employee_id == employee_id)
    if event_type:
        conditions.append(SecurityEvent.event_type == event_type)
    if outcome:
        conditions.append(SecurityEvent.outcome == outcome)
    if since:
        conditions.append(SecurityEvent.timestamp >= _parse_ts(since))
    if until:
        conditions.append(SecurityEvent.timestamp <= _parse_ts(until))
    total = db.scalar(select(func.count(SecurityEvent.id)).where(*conditions)) or 0
    items = db.scalars(
        select(SecurityEvent).where(*conditions).order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .limit(limit).offset(offset)
    ).all()
    return EventPage(total=total, limit=limit, offset=offset, items=[EventOut.model_validate(e) for e in items])


@app.get("/api/events/me", response_model=list[EventPublic], tags=["events"])
def my_events(
    auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=200)
):
    return db.scalars(
        select(SecurityEvent).where(SecurityEvent.employee_id == auth.employee.id)
        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).limit(limit)
    ).all()


# ---------------------------------------------------------------- risk
@app.get("/api/risk/employees", response_model=list[EmployeeRiskOut], tags=["risk"])
def risk_overview(_: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    scores = detection_engine.all_current_scores(db)
    rows = [
        EmployeeRiskOut(
            employee_id=e.id, username=e.username, full_name=e.full_name, department=e.department,
            status=e.status, score=scores.get(e.id, 0), level=detection_engine.level_for(scores.get(e.id, 0)),
        )
        for e in db.scalars(select(Employee).order_by(Employee.id))
    ]
    return sorted(rows, key=lambda r: r.score, reverse=True)


def _risk_detail(db: Session, employee: Employee) -> RiskDetailOut:
    now = utcnow()
    summary = detection_engine.current_risk(db, employee.id, now)
    corr = correlation_engine.correlate(db, employee.id, now)
    history = db.scalars(
        select(RiskAssessment).where(RiskAssessment.employee_id == employee.id)
        .order_by(RiskAssessment.created_at.desc(), RiskAssessment.id.desc()).limit(50)
    ).all()
    return RiskDetailOut(
        employee_id=employee.id, username=employee.username, score=summary.score, level=summary.level,
        window_minutes=get_settings().risk_window_minutes, factors=summary.factors,
        attack_stages=corr.stage_names, attack_confidence=corr.confidence,
        history=[AssessmentOut.model_validate(a) for a in history],
    )


@app.get("/api/risk/employees/{employee_id}", response_model=RiskDetailOut, tags=["risk"])
def risk_detail(employee_id: int, _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    return _risk_detail(db, _get_employee_or_404(db, employee_id))


@app.post("/api/risk/assess", response_model=RiskDetailOut, tags=["risk"])
def assess_risk(body: RiskAssessRequest, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    employee = _get_employee_or_404(db, body.employee_id)
    detection_engine.assess_employee(db, employee)
    write_audit(db, "risk_assessment_run", actor_id=auth.employee.id, target_type="employee", target_id=employee.id)
    db.commit()
    return _risk_detail(db, employee)


# ---------------------------------------------------------------- alerts
@app.get("/api/alerts", response_model=list[AlertOut], tags=["alerts"])
def list_alerts(
    _: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
    alert_status: str | None = Query(None, alias="status", pattern="^(open|investigating|contained|resolved|false_positive)$"),
    severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    employee_id: int | None = Query(None, gt=0),
    limit: int = Query(100, ge=1, le=500),
):
    query = select(SecurityAlert).order_by(SecurityAlert.updated_at.desc(), SecurityAlert.id.desc()).limit(limit)
    if alert_status:
        query = query.where(SecurityAlert.status == alert_status)
    if severity:
        query = query.where(SecurityAlert.severity == severity)
    if employee_id:
        query = query.where(SecurityAlert.employee_id == employee_id)
    return db.scalars(query).all()


@app.get("/api/alerts/{alert_id}", response_model=AlertOut, tags=["alerts"])
def get_alert(alert_id: int, _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    alert = db.get(SecurityAlert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


@app.patch("/api/alerts/{alert_id}", response_model=AlertOut, tags=["alerts"])
def update_alert(alert_id: int, body: AlertUpdate, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    alert = db.get(SecurityAlert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    previous = alert.status
    alert.status = body.status
    alert.updated_at = utcnow()
    write_audit(db, "alert_status_changed", actor_id=auth.employee.id, target_type="alert", target_id=alert.id,
                details={"from": previous, "to": body.status})
    db.commit()
    return alert


# ---------------------------------------------------------------- investigations
@app.get("/api/investigations", response_model=list[InvestigationOut], tags=["investigations"])
def list_investigations(
    _: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
    inv_status: str | None = Query(None, alias="status", pattern="^(open|contained|closed)$"),
    employee_id: int | None = Query(None, gt=0),
):
    query = select(AttackInvestigation).order_by(AttackInvestigation.updated_at.desc(), AttackInvestigation.id.desc())
    if inv_status:
        query = query.where(AttackInvestigation.status == inv_status)
    if employee_id:
        query = query.where(AttackInvestigation.employee_id == employee_id)
    return db.scalars(query).all()


def _investigation_detail(db: Session, investigation: AttackInvestigation) -> InvestigationDetail:
    actions = db.scalars(
        select(ContainmentAction).where(ContainmentAction.employee_id == investigation.employee_id,
                                        ContainmentAction.investigation_id == investigation.id)
        .order_by(ContainmentAction.id)
    ).all()
    data = {name: getattr(investigation, name) for name in InvestigationOut.model_fields}
    return InvestigationDetail(**data, containment_actions=[ContainmentOut.model_validate(a) for a in actions])


@app.get("/api/investigations/{investigation_id}", response_model=InvestigationDetail, tags=["investigations"])
def get_investigation(investigation_id: int, _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    investigation = db.get(AttackInvestigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    return _investigation_detail(db, investigation)


@app.post("/api/investigations", response_model=InvestigationDetail, status_code=status.HTTP_201_CREATED, tags=["investigations"])
def run_investigation(body: InvestigationCreate, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    """Build (or refresh the active) investigation report for an employee from stored events."""
    employee = _get_employee_or_404(db, body.employee_id)
    investigation = investigation_service.upsert_investigation(db, employee)
    write_audit(db, "investigation_run", actor_id=auth.employee.id, target_type="investigation", target_id=investigation.id,
                details={"employee_id": employee.id})
    db.commit()
    return _investigation_detail(db, investigation)


@app.patch("/api/investigations/{investigation_id}", response_model=InvestigationDetail, tags=["investigations"])
def update_investigation(
    investigation_id: int, body: InvestigationUpdate, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)
):
    investigation = db.get(AttackInvestigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    investigation.status = body.status
    investigation.closed_at = utcnow() if body.status == "closed" else None
    if body.status == "closed":
        for alert in db.scalars(select(SecurityAlert).where(SecurityAlert.investigation_id == investigation.id,
                                                            SecurityAlert.status.in_(("open", "investigating", "contained")))):
            alert.status = "resolved"
            alert.updated_at = utcnow()
    write_audit(db, "investigation_status_changed", actor_id=auth.employee.id, target_type="investigation",
                target_id=investigation.id, details={"to": body.status})
    db.commit()
    return _investigation_detail(db, investigation)


# ---------------------------------------------------------------- containment
@app.post("/api/containment", response_model=ContainmentOut, status_code=status.HTTP_201_CREATED, tags=["containment"])
def create_containment(
    body: ContainmentRequest, request: Request, auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)
):
    target = _get_employee_or_404(db, body.employee_id)
    return response_service.apply_action(
        db, auth.employee, target, body.action_type, body.reason, body.investigation_id, ip=resolve_ip(request)
    )


@app.get("/api/containment", response_model=list[ContainmentOut], tags=["containment"])
def list_containment(
    _: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
    employee_id: int | None = Query(None, gt=0),
    investigation_id: int | None = Query(None, gt=0),
    limit: int = Query(100, ge=1, le=500),
):
    query = select(ContainmentAction).order_by(ContainmentAction.id.desc()).limit(limit)
    if employee_id:
        query = query.where(ContainmentAction.employee_id == employee_id)
    if investigation_id:
        query = query.where(ContainmentAction.investigation_id == investigation_id)
    return db.scalars(query).all()


# ---------------------------------------------------------------- dashboard
@app.get("/api/dashboard/stats", response_model=DashboardStats, tags=["dashboard"])
def dashboard_stats(_: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    now = utcnow()
    day_ago = now - timedelta(hours=24)
    scores = detection_engine.all_current_scores(db)
    employees = db.scalars(select(Employee).order_by(Employee.id)).all()

    recent = db.execute(
        select(SecurityEvent.event_type, SecurityEvent.timestamp).where(SecurityEvent.timestamp >= day_ago)
    ).all()
    by_type: dict[str, int] = {}
    buckets = {}
    for offset in range(23, -1, -1):
        hour = (now - timedelta(hours=offset)).replace(minute=0, second=0, microsecond=0)
        buckets[hour] = 0
    for event_type, ts in recent:
        by_type[event_type] = by_type.get(event_type, 0) + 1
        hour = ts.replace(minute=0, second=0, microsecond=0)
        if hour in buckets:
            buckets[hour] += 1

    severity_rows = db.execute(
        select(SecurityAlert.severity, func.count(SecurityAlert.id))
        .where(SecurityAlert.status.in_(("open", "investigating"))).group_by(SecurityAlert.severity)
    ).all()
    alerts_by_severity = {level: 0 for level in ("low", "medium", "high", "critical")}
    alerts_by_severity.update({sev: n for sev, n in severity_rows})

    ranked = sorted(employees, key=lambda e: scores.get(e.id, 0), reverse=True)
    high_threshold = get_settings().risk_high_threshold
    return DashboardStats(
        generated_at=now,
        total_employees=len(employees),
        active_sessions=db.scalar(select(func.count(EmployeeSession.id)).where(
            EmployeeSession.revoked_at.is_(None), EmployeeSession.expires_at > now)) or 0,
        events_total=db.scalar(select(func.count(SecurityEvent.id))) or 0,
        events_24h=len(recent),
        open_alerts=sum(alerts_by_severity.values()),
        alerts_by_severity=alerts_by_severity,
        open_investigations=db.scalar(select(func.count(AttackInvestigation.id)).where(
            AttackInvestigation.status.in_(("open", "contained")))) or 0,
        high_risk_employees=sum(1 for e in employees if scores.get(e.id, 0) >= high_threshold),
        average_risk_score=round(sum(scores.get(e.id, 0) for e in employees) / max(len(employees), 1), 1),
        containment_actions_total=db.scalar(select(func.count(ContainmentAction.id))) or 0,
        locked_accounts=sum(1 for e in employees if e.status == "locked"),
        events_by_type_24h=by_type,
        events_per_hour_24h=[{"hour": h.isoformat(), "count": c} for h, c in buckets.items()],
        top_risk_employees=[
            EmployeeRiskOut(
                employee_id=e.id, username=e.username, full_name=e.full_name, department=e.department,
                status=e.status, score=scores.get(e.id, 0), level=detection_engine.level_for(scores.get(e.id, 0)),
            )
            for e in ranked[:5]
        ],
    )


@app.get("/api/audit-logs", tags=["system"])
def audit_logs(
    _: AuthContext = Depends(require_admin), db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=500)
):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).all()
    return [
        {"id": r.id, "actor_id": r.actor_id, "action": r.action, "target_type": r.target_type, "target_id": r.target_id,
         "ip_address": r.ip_address, "details": r.details, "timestamp": r.timestamp}
        for r in rows
    ]
