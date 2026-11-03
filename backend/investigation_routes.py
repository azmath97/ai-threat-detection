"""Investigation workflow endpoints (security administrators only): explanation, preserved evidence, export, resolution."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from backend import investigation_export, investigation_service, response_service
from backend.containment_guard import containment_admin
from backend.database import get_db
from backend.event_service import write_audit
from backend.models import AttackInvestigation
from backend.schemas import ContainmentOut, InvestigationResolve
from backend.security import AuthContext, require_admin, resolve_ip

router = APIRouter(prefix="/api/investigations", tags=["investigations"])


def _get(db: Session, investigation_id: int) -> AttackInvestigation:
    investigation = db.get(AttackInvestigation, investigation_id)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    return investigation


@router.get("/{investigation_id}/explanation")
def explanation(investigation_id: int, _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    """Evidence-based explanation: attack type, stage, activities, evidence, impact, containment, gaps, alternatives."""
    inv = _get(db, investigation_id)
    return {"investigation_id": inv.id, "status": inv.status, "explanation": inv.explanation,
            "integrity": investigation_service.integrity(db, inv)}


@router.get("/{investigation_id}/evidence")
def evidence(investigation_id: int, _: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    """The preserved events with their hashes and a live integrity check."""
    inv = _get(db, investigation_id)
    check = investigation_service.integrity(db, inv)
    bad = {*check["modified"], *check["missing"]}
    return {
        "investigation_id": inv.id, "integrity": check, "case_file": inv.case_file,
        "events": [{"event_id": r.event_id, "relations": r.relations, "sha256": r.content_hash, "collected_at": r.collected_at,
                    "integrity": "verified" if r.event_id not in bad else "modified_or_missing", "snapshot": r.snapshot}
                   for r in investigation_service.evidence_rows(db, inv.id)],
    }


@router.get("/{investigation_id}/export")
def export(investigation_id: int, request: Request, export_format: str = Query("json", alias="format", pattern="^(json|csv)$"),
           auth: AuthContext = Depends(require_admin), db: Session = Depends(get_db)):
    """Download the investigation report (JSON, or CSV of the correlated events). The export is audited."""
    inv = _get(db, investigation_id)
    report = investigation_export.build(db, inv, auth.employee)
    body = investigation_export.to_json(report) if export_format == "json" else investigation_export.to_csv(report)
    write_audit(db, "investigation_exported", actor_id=auth.employee.id, target_type="investigation", target_id=inv.id,
                ip=resolve_ip(request, auth.employee),
                details={"format": export_format, "events": len(report["correlated_events"]),
                         "sha256": investigation_export.checksum(body), "integrity_intact": report["evidence_integrity"]["intact"]})
    db.commit()
    name = f"investigation-{inv.id}-{inv.employee.employee_code}.{export_format}"
    return Response(content=body, media_type="application/json" if export_format == "json" else "text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.post("/{investigation_id}/resolve", response_model=ContainmentOut, status_code=status.HTTP_201_CREATED)
def resolve(investigation_id: int, body: InvestigationResolve, request: Request, response: Response,
            auth: AuthContext = Depends(containment_admin), db: Session = Depends(get_db)):
    """Mark the investigation resolved in this application. Needs a reason and explicit confirmation; recorded as an audited
    simulated action, and retries with the same `idempotency_key` return the original action (HTTP 200)."""
    inv = _get(db, investigation_id)
    action = response_service.apply_action(db, auth.employee, inv.employee, "resolve_investigation", body.reason, inv.id,
                                           ip=resolve_ip(request, auth.employee), confirm=body.confirm,
                                           idempotency_key=body.idempotency_key)
    if getattr(action, "replayed", False):
        response.status_code = status.HTTP_200_OK
    return action
