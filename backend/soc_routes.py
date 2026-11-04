"""SOC dashboard endpoints (security administrators only). Thin wrappers over soc_service."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend import soc_service
from backend.catalog import EVENT_TYPES, SEVERITY_LEVELS
from backend.config import get_settings
from backend.database import get_db
from backend.security import AuthContext, require_admin

router = APIRouter(prefix="/api/soc", tags=["soc"])
_MAX_PAGE = get_settings().max_page_size


@router.get("/version")
def version(_: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    """Cheap change token: clients poll this and only reload data when it changes."""
    return soc_service.version(db)


@router.get("/overview")
def overview(_: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    return soc_service.overview(db)


@router.get("/risk-history")
def risk_history(employee_id: int = Query(gt=0), minutes: int = Query(120, ge=5, le=1440),
                       _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    return soc_service.risk_history(db, employee_id, minutes)


@router.get("/events")
def events(
    employee: str | None = Query(None, max_length=16, description="Employee ID, e.g. EMP-1004"),
    ip: str | None = Query(None, max_length=45),
    event_type: str | None = Query(None),
    risk_band: str | None = Query(None, description="normal | suspicious | high_risk | critical (Normal / Watch / Elevated / Alert)"),
    minutes: int | None = Query(None, ge=1, le=60 * 24 * 90),
    limit: int = Query(100, ge=1, le=_MAX_PAGE),
    before_id: int | None = Query(None, gt=0, description="Keyset pagination: only events older than this event id"),
    _: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if event_type and event_type not in EVENT_TYPES:
        raise HTTPException(422, f"event_type must be one of {', '.join(EVENT_TYPES)}")
    if risk_band and risk_band not in SEVERITY_LEVELS:
        raise HTTPException(422, f"risk_band must be one of {', '.join(SEVERITY_LEVELS)}")
    return soc_service.event_feed(db, employee=employee, ip=ip, event_type=event_type, risk_band=risk_band,
                                  minutes=minutes, limit=limit, before_id=before_id)


@router.get("/employees")
def employees(_: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    return soc_service.employee_rows(db)


@router.get("/investigations")
def investigations(inv_status: str | None = Query(None, alias="status", pattern="^(active|open|contained|resolved)$"),
                   limit: int = Query(200, ge=1, le=_MAX_PAGE),
                   _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    return soc_service.investigation_rows(db, inv_status, limit)


@router.get("/investigations/{investigation_id}")
def investigation(investigation_id: int, _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    return soc_service.investigation_detail(db, investigation_id)


@router.get("/scopes")
def scopes(_: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    """Investigations and live employee windows that the timeline and graph can show."""
    return soc_service.scopes(db)


@router.get("/timeline")
def timeline(investigation_id: int | None = Query(None, gt=0), employee_id: int | None = Query(None, gt=0),
             _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    if not (investigation_id or employee_id):
        raise HTTPException(422, "investigation_id or employee_id is required")
    return soc_service.timeline(db, investigation_id, employee_id)


@router.get("/graph")
def graph(investigation_id: int | None = Query(None, gt=0), employee_id: int | None = Query(None, gt=0),
          minutes: int | None = Query(None, ge=5, le=1440),
          _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    if not (investigation_id or employee_id):
        raise HTTPException(422, "investigation_id or employee_id is required")
    return soc_service.graph(db, investigation_id, employee_id, minutes)


@router.get("/response")
def response_centre(_: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    return soc_service.response_centre(db)


@router.get("/audit")
def audit(category: str | None = Query(None, pattern="^(alerts|investigations|containment|administrator|failed_response)$"),
          limit: int = Query(200, ge=1, le=500), _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    return {"categories": soc_service.AUDIT_CATEGORIES, "rows": soc_service.audit_rows(db, category, limit)}
