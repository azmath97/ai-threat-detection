"""Simulation runs: start, execute in the background, observe, stop.

A run turns a seeded plan (scenario_generator.py) into real backend activity. Every action goes through the same
functions the API uses (`authenticate`, `access_resource`, `record_event`), so events are stored, scored, correlated,
alerted and investigated exactly like any other event. Nothing here writes an alert, a risk score or an investigation, and
nothing opens a network connection: destinations are `.invalid` names stored as text.

Lifecycle: queued -> running -> completed | failed | cancelled. At most one run is active at a time (enforced by a unique
database slot), a repeated start request with the same idempotency key returns the original run, and every event and
investigation a run creates is tagged with its run id so runs cannot be mixed.
"""
import logging
import threading
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend import run_context
from lab import scenario_generator as gen
from lab import simulation_service as legacy
from backend.auth_service import authenticate
from backend.catalog import SEVERITY_RANK
from backend.config import get_settings
from backend.database import SessionLocal, utcnow
from backend.detection_engine import linked_employee_ids
from backend.errors import ServiceError
from backend.event_service import access_resource, record_event, write_audit
from backend.investigation_service import ACTIVE_STATUSES
from backend.models import (
    AttackInvestigation,
    Employee,
    EmployeeSession,
    RiskAssessment,
    SecurityAlert,
    SecurityEvent,
    SimulationRun,
)
from data.demo_accounts import DEMO_USERNAMES, demo_password

logger = logging.getLogger("insider_threat.simulation")

RUN_ACTIVE = ("queued", "running")
TERMINAL_STATUSES = ("completed", "failed", "cancelled")
PACES = ("instant", "demo")
WORKSTATION_DEVICE = "Westbridge workstation (simulated)"
WRONG_PASSWORD = "Not-A-Valid-Password-Simulated"           # never matches a real credential; used for failed-login events

_lock = threading.Lock()
_cancel_events: dict[int, threading.Event] = {}


# ------------------------------------------------------------------------------------------------------- profiles
def profile_of(employee: Employee) -> gen.Profile:
    return gen.Profile(
        id=employee.id, code=employee.employee_code, username=employee.username, department=employee.department,
        job_role=employee.job_role, known_ips=tuple(employee.known_ips or ()),
        permissions=tuple(sorted((p.resource, p.access_level) for p in employee.permissions)))


def eligible_employees(db: Session) -> list[Employee]:
    """Seeded standard employees that may take part: active, not synthetic accounts, with a demo credential."""
    rows = db.scalars(select(Employee).where(Employee.role == "employee", Employee.is_synthetic.is_(False),
                                             Employee.status == "active").order_by(Employee.id))
    return [e for e in rows if e.username in DEMO_USERNAMES]


# ------------------------------------------------------------------------------------------------------- starting
def _contaminated(db: Session, target: Employee) -> str | None:
    """Why starting a run on this employee would mix evidence with an earlier run, or None if it is clean."""
    settings = get_settings()
    since = utcnow() - timedelta(minutes=settings.correlation_window_minutes)
    linked = linked_employee_ids(db, target.id)
    stale = db.scalar(select(func.count(SecurityEvent.id)).where(
        SecurityEvent.employee_id.in_(linked), SecurityEvent.is_synthetic.is_(True), SecurityEvent.risk_points > 0,
        SecurityEvent.timestamp >= since)) or 0
    open_investigation = db.scalar(select(func.count(AttackInvestigation.id)).where(
        AttackInvestigation.employee_id == target.id, AttackInvestigation.status.in_(ACTIVE_STATUSES))) or 0
    if open_investigation:
        return f"{target.username} has an open investigation from an earlier simulation; resolve it or reset the simulation first"
    if stale:
        return (f"{target.username} has {stale} flagged simulated events from the last {settings.correlation_window_minutes} "
                "minutes; a new run would be correlated with them. Choose another employee or reset the simulation")
    return None


def start_run(db: Session, admin: Employee, *, scenario: str, target_employee_id: int | None, seed: int | None,
              records: int | None, source_ip: str | None, pace: str, noise: int | None,
              idempotency_key: str | None) -> tuple[SimulationRun, bool]:
    """Create a queued run and start its worker. Returns (run, duplicate)."""
    if scenario not in gen.SCENARIO_IDS:
        raise ServiceError(422, f"scenario must be one of: {', '.join(sorted(gen.SCENARIO_IDS))}")
    if pace not in PACES:
        raise ServiceError(422, f"pace must be one of: {', '.join(PACES)}")
    with _lock:
        if idempotency_key:
            existing = db.scalar(select(SimulationRun).where(SimulationRun.idempotency_key == idempotency_key))
            if existing is not None:
                return existing, True
        active = db.scalar(select(SimulationRun).where(SimulationRun.active_slot == 1))
        if active is not None:
            raise ServiceError(409, f"Simulation run {active.id} ({active.scenario}) is still {active.status}. "
                                    "Stop it or wait for it to finish before starting another.")
        candidates = eligible_employees(db)
        seed_mode, seed = ("fixed", seed) if seed is not None else ("random", gen.new_seed())
        if target_employee_id is None:
            try:
                target_profile = gen.choose_target(scenario, seed, [profile_of(e) for e in candidates])
            except gen.PlanError as exc:
                raise ServiceError(409, str(exc)) from exc
            target = db.get(Employee, target_profile.id)
        else:
            target = db.get(Employee, target_employee_id)
            if target is None or target.is_synthetic:
                raise ServiceError(404, "Employee not found")
            if target.role != "employee" or target.username not in DEMO_USERNAMES:
                raise ServiceError(400, "Only the standard demo employee accounts can be simulated")
            if target.status != "active":
                raise ServiceError(409, f"{target.username} is locked (containment in effect); restore the account first")
        reason = _contaminated(db, target)
        if reason:
            raise ServiceError(409, reason)
        try:
            plan = gen.generate(scenario, seed, profile_of(target), [profile_of(e) for e in candidates],
                                records=records, source_ip=source_ip, noise=noise)
        except gen.PlanError as exc:
            raise ServiceError(422, str(exc)) from exc
        run = SimulationRun(
            idempotency_key=idempotency_key, scenario=scenario, seed=seed, seed_mode=seed_mode, status="queued",
            active_slot=1, target_employee_id=target.id, started_by_id=admin.id, source_ip=plan["source_ip"], pace=pace,
            parameters={"records": records, "source_ip": source_ip, "noise": noise, "pace": pace},
            plan=plan, plan_sha256=gen.plan_digest(plan), steps_total=len(plan["actions"]), steps_done=0, results=[])
        db.add(run)
        try:
            db.flush()
        except IntegrityError:           # a concurrent start won the slot or reused the key
            db.rollback()
            existing = db.scalar(select(SimulationRun).where(SimulationRun.idempotency_key == idempotency_key)) \
                if idempotency_key else None
            if existing is not None:
                return existing, True
            raise ServiceError(409, "Another simulation run is already active") from None
        write_audit(db, "simulation_run_created", actor_id=admin.id, target_type="simulation_run", target_id=run.id,
                    details={"scenario": scenario, "seed": seed, "seed_mode": seed_mode, "target": target.username,
                             "plan_sha256": run.plan_sha256, "pace": pace})
        db.commit()
        _cancel_events[run.id] = threading.Event()
    threading.Thread(target=_execute, args=(run.id,), name=f"simulation-run-{run.id}", daemon=True).start()
    return run, False


# -------------------------------------------------------------------------------------------------------- stopping
def cancel_run(db: Session, admin: Employee, run_id: int, wait_seconds: float = 5.0) -> SimulationRun:
    run = db.get(SimulationRun, run_id)
    if run is None:
        raise ServiceError(404, "Simulation run not found")
    if run.status in TERMINAL_STATUSES:
        return run
    # A run that has not started yet is cancelled atomically; one that has is asked to stop between actions.
    changed = db.execute(update(SimulationRun).where(SimulationRun.id == run_id, SimulationRun.status == "queued").values(
        status="cancelled", active_slot=None, finished_at=utcnow(), cancel_requested=True)).rowcount
    if not changed:
        db.execute(update(SimulationRun).where(SimulationRun.id == run_id).values(cancel_requested=True))
    write_audit(db, "simulation_run_cancel_requested", actor_id=admin.id, target_type="simulation_run", target_id=run_id)
    db.commit()
    event = _cancel_events.get(run_id)
    if event is not None:
        event.set()
    deadline = utcnow() + timedelta(seconds=wait_seconds)
    while utcnow() < deadline:
        db.expire_all()
        run = db.get(SimulationRun, run_id)
        if run.status in TERMINAL_STATUSES:
            break
        threading.Event().wait(0.05)
    return run


def recover_interrupted(db: Session) -> int:
    """Runs left queued/running by a previous process cannot continue; mark them failed and release the slot."""
    count = db.execute(update(SimulationRun).where(SimulationRun.status.in_(RUN_ACTIVE)).values(
        status="failed", active_slot=None, finished_at=utcnow(),
        error="Interrupted: the backend restarted while the run was active")).rowcount
    db.commit()
    return count


# ------------------------------------------------------------------------------------------------------- execution
class _Context:
    def __init__(self, db: Session, admin: Employee, run: SimulationRun, target: Employee):
        self.db, self.admin, self.run, self.target = db, admin, run, target
        self.sessions: dict[str, EmployeeSession] = {}
        self.people: dict[str, Employee] = {"target": target}

    def actor(self, name: str) -> Employee:
        if name not in self.people:
            self.people[name] = self.db.get(Employee, int(name.split(":", 1)[1]))
        return self.people[name]

    def meta(self, action: dict, **extra) -> dict:
        role = "scenario" if action["actor"] == "target" else "noise"
        base = {"sim_run": self.run.id, "sim_action": action["n"], "sim_actor": role, "scenario": self.run.scenario,
                "simulated_by": self.admin.username}
        return {**base, **{k: v for k, v in action.items() if k in ("phase", "purpose")}, **extra}

    def device(self, actor: Employee, ip: str) -> str:
        return WORKSTATION_DEVICE if ip in (actor.known_ips or []) else legacy.SIM_DEVICE

    def live_session(self, name: str) -> EmployeeSession:
        """The actor's session, re-read from the database so containment applied meanwhile takes effect."""
        actor = self.actor(name)
        self.db.refresh(actor)
        if actor.status != "active":
            raise ServiceError(403, f"Account {actor.username} is locked - containment is in effect")
        session = self.sessions.get(name)
        if session is None:
            raise ServiceError(409, f"No session for {actor.username}: the sign-in did not succeed")
        self.db.refresh(session)
        if session.revoked_at is not None or session.expires_at <= utcnow():
            raise ServiceError(409, f"The session of {actor.username} was revoked or has ended")
        return session


def _login(ctx: _Context, a: dict) -> dict:
    actor = ctx.actor(a["actor"])
    result = authenticate(ctx.db, actor.employee_code, demo_password(actor.employee_code), ip=a["ip"],
                          device_info=ctx.device(actor, a["ip"]), synthetic=True, scenario=ctx.run.scenario, details=ctx.meta(a))
    ctx.sessions[a["actor"]] = result.session
    return {"status": "completed", "detail": f"{actor.username} signed in from {a['ip']}"}


def _failed_login(ctx: _Context, a: dict) -> dict:
    actor = ctx.actor(a["actor"])
    for attempt in range(1, a["count"] + 1):
        try:
            authenticate(ctx.db, actor.employee_code, WRONG_PASSWORD, ip=a["ip"], device_info=ctx.device(actor, a["ip"]),
                         synthetic=True, scenario=ctx.run.scenario, details=ctx.meta(a, attempt=attempt))
        except ServiceError:
            pass                                              # the failed-login event has been recorded by authenticate
    return {"status": "completed", "detail": f"{a['count']} failed login(s) for {actor.username} from {a['ip']}"}


def _logout(ctx: _Context, a: dict) -> dict:
    session = ctx.live_session(a["actor"])
    actor = ctx.actor(a["actor"])
    session.revoked_at = utcnow()
    record_event(ctx.db, actor, "logout", source_ip=session.ip_address, session=session, device_info=session.device_info,
                 is_synthetic=True, scenario=ctx.run.scenario, details=ctx.meta(a), commit=False)
    write_audit(ctx.db, "logout", actor_id=actor.id, target_type="session", target_id=session.id)
    ctx.db.commit()
    return {"status": "completed", "detail": f"{actor.username} signed out"}


def _access(ctx: _Context, a: dict, *, extra: dict | None = None) -> dict:
    session = ctx.live_session(a["actor"])
    actor = ctx.actor(a["actor"])
    _, permitted = access_resource(
        ctx.db, actor, a["resource"], a["action"], source_ip=session.ip_address, session=session, record_count=a["records"],
        details=ctx.meta(a, **(extra or {})), device_info=session.device_info, is_synthetic=True, scenario=ctx.run.scenario)
    return {"status": "completed" if permitted else "denied",
            "detail": f"{a['action']} of {a['records']:,} record(s) from {a['resource']} by {actor.username}: "
                      f"{'granted' if permitted else 'denied by the permission check'}"}


def _removable(ctx: _Context, a: dict) -> dict:
    outcome = _access(ctx, {**a, "action": "download"}, extra={"channel": "removable_media", "device": a["device"]})
    outcome["detail"] = outcome["detail"].replace("download of", f"copy to removable media {a['device']} of")
    return outcome


def _external(ctx: _Context, a: dict) -> dict:
    session = ctx.live_session(a["actor"])
    actor = ctx.actor(a["actor"])
    confirmed = a["status"] == "confirmed"
    record_event(
        ctx.db, actor, "external_transfer", source_ip=session.ip_address, resource=a["resource"],
        outcome="success" if confirmed else "failure", session=session, device_info=session.device_info,
        records_accessed=a["records"], records_downloaded=a["records"], is_synthetic=True, scenario=ctx.run.scenario,
        details=ctx.meta(a, destination=a["destination"], protocol="https", transfer_status=a["status"]))
    return {"status": "completed",
            "detail": f"{a['status']} transfer of {a['records']:,} record(s) from {a['resource']} to {a['destination']} "
                      "(simulated, nothing is sent)"}


def _campaign_step(ctx: _Context, a: dict) -> dict:
    sim = legacy._Sim(ctx.db, ctx.admin, ctx.target, ctx.run.plan["source_ip"], ctx.run.scenario, a["records"],
                      a["failed_attempts"], a["probe_resources"])
    base_meta = sim.meta
    sim.meta = lambda step: {**base_meta(step), **ctx.meta(a)}          # tag the stage's events with the run like any other
    return legacy._HANDLERS[a["step"]](sim)


_ACTIONS = {"login": _login, "failed_login": _failed_login, "logout": _logout, "access": _access, "removable_media": _removable,
            "external_transfer": _external, "campaign_step": _campaign_step}


def perform(ctx: _Context, action: dict) -> dict:
    before = ctx.db.scalar(select(func.max(SecurityEvent.id))) or 0
    try:
        outcome = _ACTIONS[action["kind"]](ctx, action)
    except ServiceError as exc:
        ctx.db.rollback()
        outcome = {"status": "blocked", "detail": exc.message}
    ids = list(ctx.db.scalars(select(SecurityEvent.id).where(
        SecurityEvent.simulation_run_id == ctx.run.id, SecurityEvent.id > before).order_by(SecurityEvent.id)))
    label = action.get("step") or action["kind"]
    return {"n": action["n"], "kind": action["kind"], "step": label, "actor": action["actor"], "status": outcome["status"],
            "detail": outcome["detail"], "event_ids": ids}


def _execute(run_id: int) -> None:
    cancel = _cancel_events.get(run_id) or threading.Event()
    with SessionLocal() as db:
        started = db.execute(update(SimulationRun).where(SimulationRun.id == run_id, SimulationRun.status == "queued").values(
            status="running", started_at=utcnow())).rowcount
        db.commit()
        if not started:                                           # cancelled while queued
            _cancel_events.pop(run_id, None)
            return
        run = db.get(SimulationRun, run_id)
        final, error = "completed", None
        try:
            admin, target = db.get(Employee, run.started_by_id), db.get(Employee, run.target_employee_id)
            ctx = _Context(db, admin, run, target)
            delays = gen.pacing(run.plan, run.pace)
            with run_context.in_run(run_id):
                for index, action in enumerate(run.plan["actions"]):
                    if delays[index] and cancel.wait(delays[index]):
                        final = "cancelled"
                        break
                    db.refresh(run)
                    if run.cancel_requested:
                        final = "cancelled"
                        break
                    result = perform(ctx, action)
                    run.results = [*run.results, result]
                    run.steps_done = index + 1
                    db.commit()
        except Exception as exc:                                   # a defect or database error, not a scenario outcome
            logger.exception("simulation run %s failed", run_id)
            db.rollback()
            final, error = "failed", f"Run failed with an internal error ({type(exc).__name__}); see the server log"
        finally:
            _finish(db, run_id, final, error)
            _cancel_events.pop(run_id, None)


def _finish(db: Session, run_id: int, status: str, error: str | None) -> None:
    run = db.get(SimulationRun, run_id)
    if status != "completed":                                      # a stopped or broken run must not leave sessions behind
        open_sessions = db.scalars(select(EmployeeSession).where(
            EmployeeSession.id.in_(select(SecurityEvent.session_id).where(
                SecurityEvent.simulation_run_id == run_id, SecurityEvent.session_id.is_not(None))),
            EmployeeSession.revoked_at.is_(None)))
        for session in open_sessions:
            session.revoked_at = utcnow()
    run.status, run.error, run.active_slot, run.finished_at = status, error, None, utcnow()
    write_audit(db, "simulation_run_finished", actor_id=run.started_by_id, target_type="simulation_run", target_id=run_id,
                details={"status": status, "scenario": run.scenario, "seed": run.seed, "steps_done": run.steps_done,
                         "steps_total": run.steps_total, "error": error})
    db.commit()


# ------------------------------------------------------------------------------------------------------ reporting
def serialize(db: Session, run: SimulationRun, *, detail: bool = False) -> dict:
    target = db.get(Employee, run.target_employee_id) if run.target_employee_id else None
    out = {
        "id": run.id, "scenario": run.scenario, "status": run.status, "seed": run.seed, "seed_mode": run.seed_mode,
        "pace": run.pace, "steps_done": run.steps_done, "steps_total": run.steps_total, "plan_sha256": run.plan_sha256,
        "target": None if target is None else {"id": target.id, "employee_id": target.employee_code,
                                                "username": target.username, "full_name": target.full_name},
        "source_ip": run.source_ip, "parameters": run.parameters, "error": run.error,
        "cancel_requested": run.cancel_requested, "created_at": run.created_at, "started_at": run.started_at,
        "finished_at": run.finished_at, "variant": (run.plan or {}).get("variant", {}), "observed": observed(db, run),
    }
    if detail:
        out["plan"] = run.plan
        out["results"] = run.results
    return out


def observed(db: Session, run: SimulationRun) -> dict:
    """What the detection pipeline actually produced for this run's events (observations, not expectations)."""
    rows = db.execute(select(SecurityEvent.id, SecurityEvent.risk_flags, SecurityEvent.details)
                      .where(SecurityEvent.simulation_run_id == run.id)).all()
    ids = [r[0] for r in rows]
    rules = sorted({f["rule"] for r in rows for f in (r[1] or [])})
    levels = db.execute(select(RiskAssessment.level, RiskAssessment.score, RiskAssessment.stage)
                        .where(RiskAssessment.event_id.in_(ids or [0]))).all()
    peak = max(levels, key=lambda x: (SEVERITY_RANK[x[0]], x[1]), default=None)
    investigations = list(db.scalars(select(AttackInvestigation.id).where(AttackInvestigation.simulation_run_id == run.id)))
    alerts = list(db.scalars(select(SecurityAlert.id).where(
        SecurityAlert.investigation_id.in_(investigations or [0]) | SecurityAlert.event_id.in_(ids or [0]))))
    noise = sum(1 for r in rows if (r[2] or {}).get("sim_actor") == "noise")
    return {"events": len(ids), "scenario_events": len(ids) - noise, "noise_events": noise,
            "peak_level": peak[0] if peak else None, "peak_score": peak[1] if peak else None,
            "peak_stage": peak[2] if peak else None, "rules_fired": rules,
            "alert_ids": sorted(alerts), "investigation_ids": sorted(investigations), "alert_raised": bool(alerts)}
