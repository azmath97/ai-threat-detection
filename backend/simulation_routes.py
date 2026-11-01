"""Administrator-only simulation endpoints. Unavailable to employees and when SIMULATION_ENABLED=false."""
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import simulation_service as sim
from backend.config import get_settings
from backend.database import get_db
from backend.models import Employee
from backend.security import AuthContext, require_admin

router = APIRouter(prefix="/api/simulation", tags=["simulation"])


def require_simulation(auth: AuthContext = Depends(require_admin)) -> AuthContext:
    if not get_settings().simulation_enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Simulation environment is disabled")
    return auth


class _Target(BaseModel):
    target_employee_id: int = Field(gt=0)
    source_ip: str = Field(default=sim.DEFAULT_SOURCE_IP, description="Simulated attacker address")
    scenario: str = "it_admin_full_chain"
    records: int = Field(default=sim.EXPORT_RECORDS, ge=1, le=1_000_000, description="Records in the simulated export and transfer")

    @field_validator("source_ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError as exc:
            raise ValueError("must be a valid IPv4 or IPv6 address") from exc

    @field_validator("scenario")
    @classmethod
    def _scenario(cls, v: str) -> str:
        if v not in sim.SCENARIO_IDS:
            raise ValueError(f"must be one of: {', '.join(sorted(sim.SCENARIO_IDS))}")
        return v


class StepRequest(_Target):
    step: str


def _target(db: Session, employee_id: int) -> Employee:
    target = db.get(Employee, employee_id)
    if target is None or target.is_synthetic:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Employee not found")
    if target.role != "employee":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only standard employee accounts can be simulated")
    return target


@router.get("/scenarios")
def scenarios(_: AuthContext = Depends(require_simulation), db: Session = Depends(get_db)):
    targets = db.scalars(
        select(Employee).where(Employee.role == "employee", Employee.is_synthetic.is_(False)).order_by(Employee.id)
    )
    return {
        "scenarios": sim.SCENARIOS,
        "steps": sim.STEPS,
        "default_source_ip": sim.DEFAULT_SOURCE_IP,
        "default_records": sim.EXPORT_RECORDS,
        "targets": [
            {"id": t.id, "employee_id": t.employee_code, "username": t.username, "full_name": t.full_name,
             "department": t.department, "job_role": t.job_role, "known_ips": t.known_ips}
            for t in targets
        ],
    }


@router.get("/status")
def simulation_status(_: AuthContext = Depends(require_simulation), db: Session = Depends(get_db)):
    return sim.status(db)


@router.post("/steps")
def run_step(body: StepRequest, auth: AuthContext = Depends(require_simulation), db: Session = Depends(get_db)):
    if body.step not in sim.STEP_IDS:
        raise HTTPException(422, f"step must be one of: {', '.join(sim.STEP_IDS)}")
    return sim.run_step(db, auth.employee, _target(db, body.target_employee_id), body.step, body.source_ip, body.scenario,
                        body.records)


@router.post("/run")
def run_scenario(body: _Target, auth: AuthContext = Depends(require_simulation), db: Session = Depends(get_db)):
    results = sim.run_scenario(db, auth.employee, _target(db, body.target_employee_id), body.source_ip, body.scenario, body.records)
    return {"scenario": body.scenario, "results": results}


@router.post("/reset")
def reset(auth: AuthContext = Depends(require_simulation), db: Session = Depends(get_db)):
    return sim.reset(db, auth.employee)
