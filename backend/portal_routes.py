"""Employee portal endpoints. Identity, source IP and device always come from the authenticated request."""
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import portal_data
from backend import controls
from backend.auth_service import create_account
from backend.catalog import RESOURCES
from backend.database import get_db
from backend.event_service import has_access, record_event
from backend.models import Employee
from backend.rate_limit import enforce
from backend.security import AuthContext, device_info, get_auth, idempotency_key, resolve_ip

router = APIRouter(prefix="/api", tags=["portal"])
_PERIOD = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")


class Ctx:
    """Per-request facts the backend derives itself."""

    def __init__(self, request: Request, auth: AuthContext, db: Session):
        self.db, self.auth = db, auth
        self.ip = resolve_ip(request, auth.employee)
        self.device = device_info(request)
        self.key = idempotency_key(request)      # one page visit + action: repeats of this request store one event
        self._logged = 0

    def log(self, event_type: str, resource: str | None, *, accessed: int = 0, downloaded: int = 0,
            details: dict | None = None, outcome: str = "success"):
        self._logged += 1
        return record_event(
            self.db, self.auth.employee, event_type, source_ip=self.ip, resource=resource, outcome=outcome,
            details=details, session=self.auth.session, device_info=self.device,
            records_accessed=accessed, records_downloaded=downloaded,
            request_id=f"{self.key}#{self._logged}" if self.key else None,
        )

    def require(self, resource: str, action: str, event_type: str, details: dict | None = None) -> None:
        if has_access(self.db, self.auth.employee.id, resource, action):
            return
        reason = {"reason": "system_isolated"} if controls.is_isolated(self.db, resource) else {}
        self.log(event_type, resource, outcome="denied", details={**(details or {}), **reason, "action": action})
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Access to {RESOURCES[resource]['name']} is not permitted for your role")


def _ctx(request: Request, auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> Ctx:
    enforce("portal", auth.employee.id, "employee")
    return Ctx(request, auth, db)


def _staff(db: Session) -> list[Employee]:
    return list(db.scalars(select(Employee).where(Employee.is_synthetic.is_(False)).order_by(Employee.id)))


# ----------------------------------------------------------------- profile
@router.get("/portal/profile")
def my_profile_detail(ctx: Ctx = Depends(_ctx)):
    e = ctx.auth.employee
    data = {
        "employee_id": e.employee_code, "name": e.full_name, "email": e.email, "department": e.department,
        "job_role": e.job_role, **portal_data.hr_profile(e),
    }
    ctx.log("resource_access", "my-profile", accessed=1)
    return data


# ----------------------------------------------------------------- payslips
@router.get("/portal/payslips")
def my_payslips(ctx: Ctx = Depends(_ctx)):
    slips = portal_data.payslips(ctx.auth.employee)
    ctx.log("resource_access", "my-payslips", accessed=len(slips))
    return [{k: s[k] for k in ("period", "currency", "gross", "total_deductions", "net")} for s in slips]


@router.get("/portal/payslips/{period}")
def my_payslip(period: str, ctx: Ctx = Depends(_ctx)):
    if not _PERIOD.match(period) or period not in portal_data.recent_periods(6):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Payslip not found")
    slip = portal_data.payslip(ctx.auth.employee, period)
    ctx.log("resource_access", "my-payslips", accessed=1, details={"period": period})
    return slip


# ----------------------------------------------------------------- payroll (HR / payroll staff)
@router.get("/portal/payroll/register")
def payroll_register(ctx: Ctx = Depends(_ctx)):
    ctx.require("payroll-records", "view", "resource_access")
    rows = portal_data.payroll_register(_staff(ctx.db))
    ctx.log("resource_access", "payroll-records", accessed=len(rows), details={"view": "register"})
    return rows


@router.post("/portal/payroll/export")
def payroll_export(ctx: Ctx = Depends(_ctx)):
    enforce("payroll_export", ctx.auth.employee.id, "heavy")
    ctx.require("payroll-records", "export", "data_export", {"view": "register"})
    rows = portal_data.payroll_register(_staff(ctx.db))
    ctx.log("data_export", "payroll-records", accessed=len(rows), downloaded=len(rows),
            details={"format": "csv", "view": "register"})
    return {"filename": f"payroll_register_{rows[0]['period']}.csv", "media_type": "text/csv",
            "content": portal_data.rows_to_csv(rows), "record_count": len(rows)}


# ----------------------------------------------------------------- HR records
@router.get("/portal/hr/records")
def hr_records(q: str = Query("", max_length=100), ctx: Ctx = Depends(_ctx)):
    ctx.require("hr-records", "view", "resource_access")
    needle = q.strip().lower()
    rows = [
        {"employee_id": e.employee_code, "name": e.full_name, "department": e.department, "job_role": e.job_role,
         "status": "Active" if e.status == "active" else "Suspended"}
        for e in _staff(ctx.db)
        if not needle or needle in f"{e.full_name} {e.employee_code} {e.department} {e.job_role}".lower()
    ]
    ctx.log("resource_access", "hr-records", accessed=len(rows), details={"view": "list", "query": needle})
    return rows


@router.get("/portal/hr/records/{employee_code}")
def hr_record(employee_code: str, ctx: Ctx = Depends(_ctx)):
    ctx.require("hr-records", "view", "resource_access", {"employee_id": employee_code[:16]})
    target = next((e for e in _staff(ctx.db) if e.employee_code == employee_code.upper()), None)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Employee record not found")
    ctx.log("resource_access", "hr-records", accessed=1, details={"view": "record", "employee_id": target.employee_code})
    return {
        "employee_id": target.employee_code, "name": target.full_name, "email": target.email,
        "department": target.department, "job_role": target.job_role,
        "status": "Active" if target.status == "active" else "Suspended", **portal_data.hr_profile(target),
    }


# ----------------------------------------------------------------- documents
@router.get("/portal/documents")
def list_documents(ctx: Ctx = Depends(_ctx)):
    docs = []
    for doc in portal_data.DOCUMENTS:
        if has_access(ctx.db, ctx.auth.employee.id, doc["resource"], "view"):
            _, _, text = portal_data.document_content(doc)
            docs.append({**doc, "source": RESOURCES[doc["resource"]]["name"], "size_bytes": len(text.encode())})
    ctx.log("resource_access", "document-library", accessed=len(docs))
    return docs


@router.get("/portal/documents/{doc_id}/download")
def download_document(doc_id: str, ctx: Ctx = Depends(_ctx)):
    doc = portal_data.find_document(doc_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Document not found")
    ctx.require(doc["resource"], "download", "file_download", {"document_id": doc["id"], "title": doc["title"]})
    filename, media_type, text = portal_data.document_content(doc)
    ctx.log("file_download", doc["resource"], accessed=1, downloaded=1,
            details={"document_id": doc["id"], "title": doc["title"], "filename": filename})
    return Response(text, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ----------------------------------------------------------------- directory
@router.get("/portal/directory")
def search_directory(
    q: str = Query("", max_length=100), department: str = Query("", max_length=64), ctx: Ctx = Depends(_ctx)
):
    needle = q.strip().lower()
    rows = [
        portal_data.directory_entry(e)
        for e in _staff(ctx.db)
        if (not needle or needle in f"{e.full_name} {e.employee_code} {e.job_role} {e.email}".lower())
        and (not department or e.department == department)
    ]
    ctx.log("directory_search", "employee-directory", accessed=len(rows),
            details={"query": needle, "department": department})
    return rows


@router.get("/portal/directory/departments")
def directory_departments(_: AuthContext = Depends(get_auth), db: Session = Depends(get_db)):
    return sorted({e.department for e in _staff(db)})


# ----------------------------------------------------------------- administrative action
class AccountCreate(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[a-z][a-z0-9._-]+$")
    full_name: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("full_name")
    @classmethod
    def _clean(cls, v: str) -> str:
        return v.strip()


@router.post("/admin/accounts", status_code=status.HTTP_201_CREATED)
def create_privileged_account(body: AccountCreate, ctx: Ctx = Depends(_ctx)):
    """Create a privileged account. Needs write access to the IT admin console (denied attempts are logged)."""
    enforce("account_create", ctx.auth.employee.id, "heavy")
    account = create_account(
        ctx.db, ctx.auth.employee, ctx.auth.session, username=body.username, full_name=body.full_name,
        password=body.password, ip=ctx.ip, device_info=ctx.device,
    )
    return {"employee_id": account.employee_code, "username": account.username, "full_name": account.full_name}
