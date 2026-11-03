"""Administrator-only simulation endpoints. Unavailable to employees and when SIMULATION_ENABLED=false."""
import ipaddress
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import scenario_generator as gen
from backend import simulation_runs as runs
from backend import simulation_service as sim
from backend.config import get_settings
from backend.database import get_db
from backend.models import Employee, SimulationRun
from backend.rate_limit import enforce
from backend.security import AuthContext, require_admin

router = APIRouter(prefix="/api/simulation", tags=["simulation"])
_LABEL = re.compile(r"^[a-z0-9_]{1,64}$")


def require_simulation(auth: AuthContext = Depends(require_admin)) -> AuthContext:
    if not get_settings().simulation_enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Simulation environment is disabled")
    return auth


def simulation_limited(name: str, tier: str = "sensitive"):
    """Admin + simulation-enabled + per-minute limit, for the state-changing simulation routes."""
    def dependency(auth: AuthContext = Depends(require_simulation)) -> AuthContext:
        enforce(name, auth.employee.id, tier)
        return auth

    return dependency


def _valid_ip(v: str) -> str:
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError as exc:
        raise ValueError("must be a valid IPv4 or IPv6 address") from exc


class StepRequest(BaseModel):
    target_employee_id: int = Field(gt=0)
    step: str
    source_ip: str = Field(default=sim.DEFAULT_SOURCE_IP, description="Simulated attacker address")
    scenario: str = Field(default="manual_steps", description="Free label stored on the events")
    records: int = Field(default=sim.EXPORT_RECORDS, ge=1, le=1_000_000, description="Records in the simulated export and transfer")

    @field_validator("source_ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        return _valid_ip(v)

    @field_validator("scenario")
    @classmethod
    def _label(cls, v: str) -> str:
        if not _LABEL.match(v):
            raise ValueError("must be 1-64 characters: lowercase letters, digits and underscores")
        return v


class RunRequest(BaseModel):
    scenario: str
    target_employee_id: int | None = Field(default=None, gt=0, description="Omit to let the seed choose an eligible employee")
    seed: int | None = Field(default=None, ge=0, lt=2**31, description="Fixed seed for a reproducible run; omit for a random one")
    records: int | None = Field(default=None, ge=1, le=gen.MAX_RECORDS, description="Overrides the primary transfer volume")
    source_ip: str | None = Field(default=None, description="Overrides the simulated external address (scenarios that use one)")
    pace: Literal["instant", "demo"] = "demo"
    noise: int | None = Field(default=None, ge=0, le=3, description="Number of other employees generating benign activity")
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$",
                                        description="Repeating a request with the same key returns the original run")

    @field_validator("source_ip")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        return None if v is None else _valid_ip(v)

    @field_validator("scenario")
    @classmethod
    def _scenario(cls, v: str) -> str:
        if v not in gen.SCENARIO_IDS:
            raise ValueError(f"must be one of: {', '.join(sorted(gen.SCENARIO_IDS))}")
        return v


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
        "scenarios": gen.SCENARIOS,
        "steps": sim.STEPS,
        "paces": list(runs.PACES),
        "default_source_ip": sim.DEFAULT_SOURCE_IP,
        "default_records": sim.EXPORT_RECORDS,
        "targets": [
            {"id": t.id, "employee_id": t.employee_code, "username": t.username, "full_name": t.full_name,
             "department": t.department, "job_role": t.job_role, "known_ips": t.known_ips,
             "eligible": {s["id"]: gen.eligible(s["id"], runs.profile_of(t)) for s in gen.SCENARIOS}}
            for t in targets
        ],
    }


@router.get("/status")
def simulation_status(_: AuthContext = Depends(require_simulation), db: Session = Depends(get_db)):
    return sim.status(db)


@router.post("/steps")
def run_step(body: StepRequest, auth: AuthContext = Depends(simulation_limited("simulation_step")), db: Session = Depends(get_db)):
    if body.step not in sim.STEP_IDS:
        raise HTTPException(422, f"step must be one of: {', '.join(sim.STEP_IDS)}")
    active = db.scalar(select(SimulationRun).where(SimulationRun.active_slot == 1))
    if active is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Simulation run {active.id} is {active.status}; manual steps are "
                                                      "disabled until it finishes or is stopped")
    return sim.run_step(db, auth.employee, _target(db, body.target_employee_id), body.step, body.source_ip, body.scenario,
                        body.records)


@router.post("/runs", status_code=status.HTTP_202_ACCEPTED)
def start_run(body: RunRequest, auth: AuthContext = Depends(simulation_limited("simulation_run")), db: Session = Depends(get_db)):
    run, duplicate = runs.start_run(
        db, auth.employee, scenario=body.scenario, target_employee_id=body.target_employee_id, seed=body.seed,
        records=body.records, source_ip=body.source_ip, pace=body.pace, noise=body.noise,
        idempotency_key=body.idempotency_key)
    return {**runs.serialize(db, run, detail=True), "duplicate_request": duplicate}


@router.get("/runs")
def list_runs(limit: int = Query(10, ge=1, le=50), _: AuthContext = Depends(require_simulation), db: Session = Depends(get_db)):
    rows = db.scalars(select(SimulationRun).order_by(SimulationRun.id.desc()).limit(limit)).all()
    return {"items": [runs.serialize(db, r) for r in rows]}


@router.get("/runs/{run_id}")
def get_run(run_id: int, _: AuthContext = Depends(require_simulation), db: Session = Depends(get_db)):
    run = db.get(SimulationRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Simulation run not found")
    return runs.serialize(db, run, detail=True)


@router.post("/runs/{run_id}/cancel")
def cancel_run(run_id: int, auth: AuthContext = Depends(simulation_limited("simulation_cancel")), db: Session = Depends(get_db)):
    return runs.serialize(db, runs.cancel_run(db, auth.employee, run_id), detail=True)


@router.post("/reset")
def reset(auth: AuthContext = Depends(simulation_limited("simulation_reset", "heavy")), db: Session = Depends(get_db)):
    return sim.reset(db, auth.employee)
