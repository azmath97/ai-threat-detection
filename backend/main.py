import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend import (
    auth_defense_routes,
    baseline as baseline_service,
    event_service,
    export_policy,
    investigation_routes,
    investigation_service,
    portal_routes,
    response_service,
    rules,
    scoring,
    simulation_routes,
    soc_routes,
    threat_engine,
)
from backend.auth_service import authenticate, find_employee
from backend.denial_monitor import AccessDenialMiddleware
from backend.catalog import (
    EVENT_TO_ACTION,
    EVENT_TYPES,
    RESOURCE_EVENT_TYPES,
    RESOURCES,
    SENSITIVITY_LABELS,
    SEVERITY_LEVELS,
    is_self_service,
)
from backend.config import get_settings, validate_for_environment
from backend.database import SessionLocal, check_database, database_info, engine, get_db, init_db, utcnow
from backend.errors import ServiceError
from backend.event_service import write_audit
from backend.rate_limit import login_ip_throttle, login_throttle
from backend.route_limits import admin_limited, employee_limited
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
from backend.containment_guard import containment_admin
from backend.hardening import (
    HttpsRequiredMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
    install_error_handlers,
)
from backend.security import AuthContext, device_info, get_auth, idempotency_key, require_admin, resolve_ip
from ml.anomaly_detector import ensure_model, get_detector, reload_detector

logger = logging.getLogger("insider_threat")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    validate_for_environment()
    init_db()
    from backend import simulation_runs

    with SessionLocal() as db:
        interrupted = simulation_runs.recover_interrupted(db)
    if interrupted:
        logger.warning("Marked %s interrupted simulation run(s) as failed", interrupted)
    detector = ensure_model()  # loads the saved Isolation Forest (trains one on first start); falls back if unavailable
    logger.info("Anomaly detection mode: %s", detector.status()["mode"])
    if get_settings().auto_seed:
        from data.seed_data import seed_database

        with SessionLocal() as db:
            if seed_database(db):
                logger.info("Seeded synthetic demo data")
    from data.demo_accounts import credentials_source_available
    from data.seed_data import sync_demo_passwords

    if get_settings().auto_seed or credentials_source_available():
        with SessionLocal() as db:
            updated = sync_demo_passwords(db)
        if updated:
            logger.warning("Updated the password hashes of %s demo account(s) to match the current credential source", updated)
    yield


_settings = get_settings()
app = FastAPI(
    title="AI-Based Insider Threat Detection API",
    description="Single source of truth for the Employee Portal and SOC Dashboard (synthetic data only).",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if _settings.enable_api_docs else None,
    redoc_url="/redoc" if _settings.enable_api_docs else None,
    openapi_url="/openapi.json" if _settings.enable_api_docs else None,
)
# Innermost first. Browsers are not expected to call this API (the dashboards call it server-side with a bearer token and no
# cookies), so CORS lists explicit origins only, allows no credentials and names the methods and headers it accepts.
app.add_middleware(AccessDenialMiddleware)          # innermost: sees only what the application itself refused
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Device-Info", "X-Frontend-Key"],
    max_age=600,
)
app.add_middleware(HttpsRequiredMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
install_error_handlers(app)


app.include_router(portal_routes.router)
app.include_router(simulation_routes.router)
app.include_router(soc_routes.router)
app.include_router(auth_defense_routes.router)
app.include_router(investigation_routes.router)


@app.exception_handler(ServiceError)
async def service_error_handler(_request: Request, exc: ServiceError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.exception_handler(OverflowError)
async def overflow_handler(_request: Request, _exc: OverflowError):
    """An integer too large for SQLite (for example a huge ID in the URL) is a client error, not a server fault."""
    return JSONResponse(status_code=422, content={"detail": "A numeric value is out of range"})


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
def health():
    try:
        check_database()
    except Exception:
        logger.exception("Health check: database unavailable")
        return JSONResponse(status_code=503, content={"status": "unavailable"}, headers={"Retry-After": "2"})
    return {"status": "ok", "time": utcnow().isoformat(), "display_timezone": get_settings().display_timezone}


@app.get("/api/system/database", tags=["system"])
def database_status(_: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    """Which store the backend uses (redacted), its schema version and row counts. Administrators only."""
    from backend import migrations

    tables = {"employees": Employee, "security_events": SecurityEvent, "security_alerts": SecurityAlert,
              "attack_investigations": AttackInvestigation, "containment_actions": ContainmentAction}
    return {**database_info(), "schema_version": migrations.current_version(engine),
            "latest_schema_version": migrations.CURRENT_VERSION,
            "row_counts": {name: db.scalar(select(func.count(model.id))) or 0 for name, model in tables.items()}}


# ---------------------------------------------------------------- auth
@app.post("/api/auth/login", response_model=LoginResponse, tags=["auth"])
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    employee = find_employee(db, body.identifier)
    ip = resolve_ip(request, employee)
    wait = max(login_throttle.retry_after(body.identifier), login_ip_throttle.retry_after(ip))
    if wait:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed sign-in attempts. Try again later.",
                            headers={"Retry-After": str(wait)})
    try:
        result = authenticate(db, body.identifier, body.password, ip=ip, device_info=device_info(request))
    except ServiceError as exc:
        if exc.status_code in (401, 403):
            if login_ip_throttle.record_failure(ip):
                event_service.write_audit(db, "login_throttled", actor_id=employee.id if employee else None, ip=ip,
                                          details={"scope": "source_ip", "lockout_seconds": get_settings().login_ip_window_seconds})
                db.commit()
            if login_throttle.record_failure(body.identifier):
                event_service.write_audit(db, "login_throttled", actor_id=employee.id if employee else None, ip=ip,
                                          details={"identifier": body.identifier[:64],
                                                   "lockout_seconds": get_settings().login_lockout_seconds})
                db.commit()
        raise
    login_throttle.record_success(body.identifier)
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
    auth: AuthContext = Depends(employee_limited("resource_access")),
    db: Session = Depends(get_db),
):
    meta = RESOURCES.get(resource_id)
    if meta is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    result, permitted = event_service.access_resource(
        db, auth.employee, resource_id, body.action, source_ip=resolve_ip(request, auth.employee),
        session=auth.session, record_count=body.record_count, device_info=device_info(request),
        request_id=idempotency_key(request), approval_id=body.approval_id,
    )
    if result.export_decision is not None and not result.export_decision.allowed:
        raise export_policy.http_error(result.export_decision)
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
    body: EventCreate, request: Request, auth: AuthContext = Depends(employee_limited("event_create")), db: Session = Depends(get_db)
):
    """Telemetry for the authenticated employee only; identity, IP and device are derived by the backend.

    Send `request_id` (or an `Idempotency-Key` header) so a retried request is stored and scored only once.
    """
    ip, device = resolve_ip(request, auth.employee), device_info(request)
    request_id = idempotency_key(request, body.request_id)
    if body.event_type in RESOURCE_EVENT_TYPES:
        result, _ = event_service.access_resource(
            db, auth.employee, body.resource, EVENT_TO_ACTION[body.event_type], source_ip=ip, session=auth.session,
            record_count=body.record_count, details=body.details, device_info=device, request_id=request_id,
        )
    else:
        outcome = "denied" if body.event_type == "permission_change_attempt" else "success"
        result = event_service.record_event(
            db, auth.employee, body.event_type, source_ip=ip, resource=body.resource, outcome=outcome,
            details=body.details, session=auth.session, device_info=device, request_id=request_id,
            records_accessed=body.record_count, records_downloaded=body.record_count if outcome == "success" else 0,
        )

    if auth.is_admin and result.assessment is not None:
        return EventCreated(event=EventPublic.model_validate(result.event), risk_score=result.assessment.score,
                            risk_level=result.assessment.level, impact_severity=result.assessment.impact_severity,
                            evidence_strength=result.assessment.evidence_strength,
                            alert_id=result.alert.id if result.alert else None, duplicate=result.duplicate)
    return EventCreated(event=EventPublic.model_validate(result.event), duplicate=result.duplicate)


def _parse_ts(raw: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(422, f"Invalid timestamp '{raw}'")
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
    limit: int = Query(100, ge=1, le=get_settings().max_page_size),
    offset: int = Query(0, ge=0),
):
    if event_type is not None and event_type not in EVENT_TYPES:
        raise HTTPException(422, f"event_type must be one of {', '.join(EVENT_TYPES)}")
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
def _risk_row(e: Employee, threat: threat_engine.ThreatAssessment) -> EmployeeRiskOut:
    return EmployeeRiskOut(
        employee_id=e.id, username=e.username, full_name=e.full_name, department=e.department, status=e.status,
        score=threat.score, level=threat.level, impact_severity=threat.impact_severity,
        evidence_strength=threat.evidence_strength, current_stage=threat.stage, stage_label=threat.stage_label,
        data_exposure=threat.exposure.get("status", "none"),
    )


@app.get("/api/risk/employees", response_model=list[EmployeeRiskOut], tags=["risk"])
def risk_overview(_: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    threats = threat_engine.assess_all(db)
    rows = [_risk_row(e, threats[e.id]) for e in db.scalars(select(Employee).order_by(Employee.id))]
    return sorted(rows, key=lambda r: r.score, reverse=True)


def _risk_detail(db: Session, employee: Employee) -> RiskDetailOut:
    threat = threat_engine.assess(db, employee)
    corr = threat.correlation
    history = db.scalars(
        select(RiskAssessment).where(RiskAssessment.employee_id == employee.id)
        .order_by(RiskAssessment.created_at.desc(), RiskAssessment.id.desc()).limit(50)
    ).all()
    return RiskDetailOut(
        employee_id=employee.id, username=employee.username, score=threat.score, risk_score=threat.risk_score,
        level=threat.level, impact_severity=threat.impact_severity, evidence_strength=threat.evidence_strength,
        window_minutes=get_settings().correlation_window_minutes, factors=threat.factors,
        attack_stages=threat.stage_names,
        current_stage=threat.stage, stage_label=threat.stage_label,
        stage_history=corr.stage_history if corr else [], independent_stages=threat.counted_stages,
        components=threat.components, score_breakdown=threat.breakdown, impact=threat.impact, strength=threat.strength,
        ml=threat.ml.as_dict() if threat.ml else None, features=threat.features,
        exposure=threat.exposure, evidence=[ev.as_dict() for ev in corr.evidence] if corr else [],
        links=corr.links if corr else {}, first_event_id=corr.first_event_id if corr else None,
        recommended_actions=threat_engine.recommend_actions(threat),
        history=[AssessmentOut.model_validate(a) for a in history],
    )


@app.get("/api/risk/employees/{employee_id}", response_model=RiskDetailOut, tags=["risk"])
def risk_detail(employee_id: int, _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    return _risk_detail(db, _get_employee_or_404(db, employee_id))


@app.post("/api/risk/assess", response_model=RiskDetailOut, tags=["risk"])
def assess_risk(body: RiskAssessRequest, auth: AuthContext = Depends(admin_limited("risk_assess")), db: Session = Depends(get_db)):
    employee = _get_employee_or_404(db, body.employee_id)
    threat = threat_engine.assess(db, employee)
    db.add(threat_engine.to_row(threat, None))
    write_audit(db, "risk_assessment_run", actor_id=auth.employee.id, target_type="employee", target_id=employee.id)
    db.commit()
    return _risk_detail(db, employee)


# ---------------------------------------------------------------- detection engine
@app.get("/api/detection/status", tags=["detection"])
def detection_status(_: AuthContext = Depends(require_admin)):
    """ML model state (Isolation Forest or fallback), thresholds and rule configuration."""
    s = get_settings()
    return {
        "data_notice": ("All training and evaluation data is synthetic: project-generated sessions and, for external "
                        "benchmarking, the CERT Insider Threat Test Dataset (synthetic users and synthetic malicious actors). "
                        "None of it is real banking data."),
        "model": get_detector().status(),
        "score_definitions": scoring.DEFINITIONS,
        "thresholds": {"suspicious": s.threat_suspicious_threshold, "high_risk": s.threat_high_threshold,
                       "critical": s.threat_critical_threshold, "alert_min_severity": s.alert_min_severity,
                       "source": s.thresholds_source, "ml_corroboration_threshold": s.ml_corroboration_threshold},
        "operating_point": scoring.operating_point_summary(),
        "correlation_window_minutes": s.correlation_window_minutes,
        "baseline_days": s.baseline_days,
        "rules": rules.summary(),
    }


@app.post("/api/detection/reload", tags=["detection"])
def detection_reload(auth: AuthContext = Depends(admin_limited("detection_reload", "heavy")), db: Session = Depends(get_db)):
    """Re-read detection_rules.json and the saved model without restarting."""
    rules.reload_rules()
    baseline_service.clear_cache()
    detector = reload_detector()
    write_audit(db, "detection_reloaded", actor_id=auth.employee.id)
    db.commit()
    return {"model_mode": detector.status()["mode"], "rules": len(rules.rules())}


@app.post("/api/detection/retrain", tags=["detection"])
def detection_retrain(auth: AuthContext = Depends(admin_limited("detection_retrain", "heavy")), db: Session = Depends(get_db)):
    """Retrain the Isolation Forest on synthetic normal behaviour, save it and load it."""
    from ml.train_model import train

    metrics = train()
    detector = reload_detector()
    write_audit(db, "model_retrained", actor_id=auth.employee.id, details={"roc_auc": metrics["roc_auc"]})
    db.commit()
    return {"model_mode": detector.status()["mode"], "metrics": metrics}


# ---------------------------------------------------------------- alerts
@app.get("/api/alerts", response_model=list[AlertOut], tags=["alerts"])
def list_alerts(
    _: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
    alert_status: str | None = Query(None, alias="status", pattern="^(open|investigating|contained|resolved|false_positive)$"),
    risk_band: str | None = Query(None, pattern="^(normal|suspicious|high_risk|critical)$"),
    impact_severity: str | None = Query(None, pattern="^(none|low|medium|high|critical)$"),
    employee_id: int | None = Query(None, gt=0),
    limit: int = Query(100, ge=1, le=get_settings().max_page_size),
):
    query = select(SecurityAlert).order_by(SecurityAlert.updated_at.desc(), SecurityAlert.id.desc()).limit(limit)
    if alert_status:
        query = query.where(SecurityAlert.status == alert_status)
    if risk_band:
        query = query.where(SecurityAlert.severity == risk_band)
    if impact_severity:
        query = query.where(SecurityAlert.impact_severity == impact_severity)
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
def update_alert(alert_id: int, body: AlertUpdate, auth: AuthContext = Depends(admin_limited("alert_update")), db: Session = Depends(get_db)):
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
    inv_status: str | None = Query(None, alias="status", pattern="^(open|contained|resolved)$"),
    employee_id: int | None = Query(None, gt=0),
    limit: int = Query(100, ge=1, le=get_settings().max_page_size),
):
    query = select(AttackInvestigation).order_by(AttackInvestigation.updated_at.desc(), AttackInvestigation.id.desc()).limit(limit)
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
def run_investigation(body: InvestigationCreate, auth: AuthContext = Depends(admin_limited("investigation_create")), db: Session = Depends(get_db)):
    """Build (or refresh the active) investigation report for an employee from stored events."""
    employee = _get_employee_or_404(db, body.employee_id)
    investigation = investigation_service.upsert_investigation(db, employee)
    write_audit(db, "investigation_run", actor_id=auth.employee.id, target_type="investigation", target_id=investigation.id,
                details={"employee_id": employee.id})
    db.commit()
    return _investigation_detail(db, investigation)


@app.patch("/api/investigations/{investigation_id}", response_model=InvestigationDetail, tags=["investigations"])
def update_investigation(
    investigation_id: int, body: InvestigationUpdate, auth: AuthContext = Depends(admin_limited("investigation_update")),
    db: Session = Depends(get_db)
):
    """Reopen a resolved investigation. Resolving is a confirmed containment action: POST /{id}/resolve."""
    investigation = db.get(AttackInvestigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    if investigation.status != "resolved":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only a resolved investigation can be reopened")
    if investigation_service.active_for(db, investigation.employee) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "The employee already has an active investigation")
    investigation.status = "open"
    investigation.closed_at = None
    write_audit(db, "investigation_status_changed", actor_id=auth.employee.id, target_type="investigation",
                target_id=investigation.id, details={"to": "open", "from": "resolved"})
    db.commit()
    return _investigation_detail(db, investigation)


# ---------------------------------------------------------------- containment
@app.post("/api/containment", response_model=ContainmentOut, status_code=status.HTTP_201_CREATED, tags=["containment"])
def create_containment(
    body: ContainmentRequest, request: Request, response: Response, auth: AuthContext = Depends(containment_admin),
    db: Session = Depends(get_db),
):
    """Run a simulated containment action against this application's own records. A retry with the same
    `idempotency_key` returns the original action with HTTP 200 and `replayed: true`."""
    target = _get_employee_or_404(db, body.employee_id)
    action = response_service.apply_action(
        db, auth.employee, target, body.action_type, body.reason, body.investigation_id, ip=resolve_ip(request, auth.employee),
        confirm=body.confirm, value=body.target, alert_id=body.alert_id, idempotency_key=body.idempotency_key,
    )
    if getattr(action, "replayed", False):
        response.status_code = status.HTTP_200_OK
    return action


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
    threats = threat_engine.assess_all(db)
    employees = db.scalars(select(Employee).order_by(Employee.id)).all()
    scores = {e.id: threats[e.id].score for e in employees}

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
    alerts_by_risk_band = {level: 0 for level in SEVERITY_LEVELS}
    alerts_by_risk_band.update({sev: n for sev, n in severity_rows})

    ranked = sorted(employees, key=lambda e: scores.get(e.id, 0), reverse=True)
    high_threshold = get_settings().threat_high_threshold
    return DashboardStats(
        generated_at=now,
        total_employees=len(employees),
        active_sessions=db.scalar(select(func.count(EmployeeSession.id)).where(
            EmployeeSession.revoked_at.is_(None), EmployeeSession.expires_at > now)) or 0,
        events_total=db.scalar(select(func.count(SecurityEvent.id))) or 0,
        events_24h=len(recent),
        open_alerts=sum(alerts_by_risk_band.values()),
        alerts_by_risk_band=alerts_by_risk_band,
        open_investigations=db.scalar(select(func.count(AttackInvestigation.id)).where(
            AttackInvestigation.status.in_(("open", "contained")))) or 0,
        high_risk_employees=sum(1 for e in employees if scores.get(e.id, 0) >= high_threshold),
        average_risk_score=round(sum(scores.get(e.id, 0) for e in employees) / max(len(employees), 1), 1),
        containment_actions_total=db.scalar(select(func.count(ContainmentAction.id))) or 0,
        locked_accounts=sum(1 for e in employees if e.status == "locked"),
        events_by_type_24h=by_type,
        events_per_hour_24h=[{"hour": h.isoformat(), "count": c} for h, c in buckets.items()],
        top_risk_employees=[_risk_row(e, threats[e.id]) for e in ranked[:5]],
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
