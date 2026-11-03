"""Seeded scenario generator and simulation runs: variety, reproducibility, safety, controls and run isolation."""
import json
import socket
import sqlite3
import time
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import auth_header, employee_id, run_scenario, wait_for_run

from backend import scenario_generator as gen
from backend import simulation_runs as runs
from backend.database import SessionLocal
from backend.models import Employee, SimulationRun

REQUIRED = {"benign_activity", "benign_bulk_transfer", "gradual_collection_staging", "bulk_export",
            "suspicious_external_transfer", "removable_media", "correlated_low_signals"}
ALL = sorted(gen.SCENARIO_IDS)
LEVELS = ["normal", "suspicious", "high_risk", "critical"]


def _profile(i, department="Finance", ips=None, perms=None):
    perms = perms or {"financial-reports": "write", "payroll-records": "read", "customer-accounts": "read",
                      "loan-applications": "read", "internal-wiki": "read"}
    return gen.Profile(i, f"EMP-{1000 + i}", f"user{i}", department, "Analyst", tuple(ips or [f"10.1.0.{i}"]),
                       tuple(sorted(perms.items())))


PEERS = [_profile(i) for i in range(1, 7)]
TARGET = PEERS[0]


def _db(db_path, sql, args=()):
    with sqlite3.connect(db_path) as con:
        return con.execute(sql, args).fetchall()


def _reset(client, admin):
    assert client.post("/api/simulation/reset", headers=admin).status_code == 200


def _events(db_path, run_id):
    rows = _db(db_path, "select id, employee_id, event_type, resource, outcome, source_ip, records_downloaded, risk_points, "
                        "details, session_id from security_events where simulation_run_id=? order by id", (run_id,))
    return [(*r[:8], json.loads(r[8]), r[9]) for r in rows]


# ------------------------------------------------------------------------------------------ generator (pure)
def test_every_required_scenario_is_offered_and_the_catalogue_is_consistent():
    assert REQUIRED <= gen.SCENARIO_IDS
    assert {s["category"] for s in gen.SCENARIOS} == {"benign", "malicious"}
    assert all(s["description"] and s["intent"] for s in gen.SCENARIOS)


@pytest.mark.parametrize("scenario", ALL)
def test_the_same_seed_gives_the_same_plan_and_other_seeds_give_different_ones(scenario):
    a = gen.generate(scenario, 11, TARGET, PEERS)
    b = gen.generate(scenario, 11, TARGET, PEERS)
    assert a == b and gen.plan_digest(a) == gen.plan_digest(b)
    digests = {gen.plan_digest(gen.generate(scenario, s, TARGET, PEERS)) for s in range(40)}
    assert len(digests) >= 35


@pytest.mark.parametrize("scenario", ALL)
def test_timing_volume_order_and_noise_vary_within_bounds(scenario):
    plans = [gen.generate(scenario, s, TARGET, PEERS) for s in range(60)]
    assert len({tuple(a["kind"] + a.get("resource", "") for a in p["actions"]) for p in plans}) >= 15      # sequence varies
    assert len({a["delay_ms"] for p in plans for a in p["actions"]}) > 100                                   # timing varies
    assert len({len(p["noise_employee_ids"]) for p in plans}) >= 3                                            # noise varies
    for p in plans:
        assert p["actions"][0]["delay_ms"] == 0 and all(250 <= a["delay_ms"] <= 2200 for a in p["actions"][1:])
        assert all(1 <= a.get("records", 1) <= gen.MAX_RECORDS for a in p["actions"])
        assert len(p["noise_employee_ids"]) <= 3 and TARGET.id not in p["noise_employee_ids"]
        assert len(p["actions"]) <= 60
    volumes = {a["records"] for p in plans for a in p["actions"]
               if a["kind"] in ("access", "removable_media", "external_transfer", "campaign_step") and a["records"] > 100}
    if scenario not in ("benign_activity", "correlated_low_signals"):
        assert len(volumes) > 20


@pytest.mark.parametrize("scenario", ALL)
def test_ordering_constraints_always_hold(scenario):
    for seed in range(60):
        plan = gen.generate(scenario, seed, TARGET, PEERS)
        by_actor: dict[str, list[dict]] = {}
        for action in plan["actions"]:
            by_actor.setdefault(action["actor"], []).append(action)
        assert [a["n"] for a in plan["actions"]] == list(range(1, len(plan["actions"]) + 1))
        for actor, chain in by_actor.items():
            kinds = [a["kind"] for a in chain]
            first_login = next(i for i, k in enumerate(kinds) if k in ("login", "failed_login"))
            assert all(k not in ("access", "removable_media", "external_transfer", "campaign_step", "logout") for k in kinds[:first_login])
            if "logout" in kinds:
                assert kinds.index("logout") == len(kinds) - 1                      # nothing after the session ends
        target_chain = by_actor["target"]
        if scenario == "suspicious_external_transfer":
            kinds = [(a["kind"], a.get("phase")) for a in target_chain]
            assert kinds.index(("access", "collection")) < kinds.index(("external_transfer", None))
        if scenario == "gradual_collection_staging":
            phases = [a.get("phase") for a in target_chain if a.get("phase")]
            assert phases.index("staging") > max(i for i, p in enumerate(phases) if p == "collection")
        if scenario == "compromised_account_campaign":
            steps = [a["step"] for a in target_chain if a["kind"] == "campaign_step"]
            if "privileged_login" in steps:
                assert steps.index("create_privileged_account") < steps.index("privileged_login")
            if "external_transfer" in steps and "large_export" in steps:
                assert steps.index("external_transfer") > steps.index("large_export")
            assert {"restricted_access", "large_export"} & set(steps)


def test_gradual_collection_grows_before_staging():
    for seed in range(30):
        plan = gen.generate("gradual_collection_staging", seed, TARGET, PEERS)
        volumes = [a["records"] for a in plan["actions"] if a.get("phase") == "collection"]
        assert len(volumes) >= 4 and volumes == sorted(volumes) and volumes[-1] > volumes[0]


def test_everything_generated_is_synthetic_and_unroutable():
    for scenario in ALL:
        for seed in range(40):
            plan = gen.generate(scenario, seed, TARGET, PEERS)
            if plan["source_ip"]:
                prefix = plan["source_ip"].rsplit(".", 1)[0]
                assert prefix in gen.DOC_NETS and plan["source_ip"] not in TARGET.known_ips
            for action in plan["actions"]:
                if action["kind"] == "login":
                    assert action["ip"] == plan["source_ip"] or action["ip"].startswith("10.1.0.")
                if action["kind"] == "external_transfer":
                    assert action["destination"].endswith(".invalid")
    assert all(d.endswith(".invalid") for d in gen.DESTINATIONS)


def test_record_override_noise_and_source_ip_are_honoured():
    plan = gen.generate("bulk_export", 3, TARGET, PEERS, records=7777, noise=0, source_ip="198.51.100.9")
    assert plan["noise_employee_ids"] == [] and {a["actor"] for a in plan["actions"]} == {"target"}
    assert any(a.get("records") == 7777 for a in plan["actions"])
    assert len(gen.generate("bulk_export", 3, TARGET, PEERS, noise=9)["noise_employee_ids"]) <= 3


def test_a_target_that_cannot_play_a_scenario_is_refused():
    plain = _profile(9, perms={"internal-wiki": "read"})
    with pytest.raises(gen.PlanError):
        gen.generate("bulk_export", 1, plain, PEERS)
    with pytest.raises(gen.PlanError):
        gen.generate("benign_bulk_transfer", 1, replace(TARGET, known_ips=()), PEERS)
    with pytest.raises(gen.PlanError):
        gen.generate("not_a_scenario", 1, TARGET, PEERS)
    assert gen.generate("benign_activity", 1, plain, PEERS)["actions"]
    assert gen.choose_target("bulk_export", 5, [plain, TARGET]).id == TARGET.id
    with pytest.raises(gen.PlanError):
        gen.choose_target("bulk_export", 5, [plain])


def test_pacing_is_bounded_and_instant_skips_waiting():
    plan = gen.generate("compromised_account_campaign", 4, TARGET, PEERS)
    assert all(w == 0 for w in gen.pacing(plan, "instant"))
    assert sum(gen.pacing(plan, "demo")) <= gen.MAX_DEMO_SECONDS + 1e-6


def test_the_generator_and_runner_never_create_alerts_scores_or_investigations():
    for name in ("scenario_generator.py", "simulation_runs.py"):
        text = Path(__file__).resolve().parent.parent.joinpath("backend", name).read_text(encoding="utf-8")
        for forbidden in ("SecurityAlert(", "RiskAssessment(", "AttackInvestigation(", "upsert_investigation", "_maybe_raise_alert"):
            assert forbidden not in text, (name, forbidden)


# --------------------------------------------------------------------------------------------- API validation
def test_run_endpoints_require_an_administrator(client, admin):
    alice = auth_header(client, "EMP-1001")
    body = {"scenario": "benign_activity", "pace": "instant"}
    for call in (lambda h: client.post("/api/simulation/runs", json=body, headers=h),
                 lambda h: client.get("/api/simulation/runs", headers=h),
                 lambda h: client.get("/api/simulation/runs/1", headers=h),
                 lambda h: client.post("/api/simulation/runs/1/cancel", headers=h)):
        assert call(alice).status_code == 403
        assert call({}).status_code == 401


@pytest.mark.parametrize("body", [
    {"scenario": "nope"}, {"scenario": "bulk_export", "seed": -1}, {"scenario": "bulk_export", "seed": 2**31},
    {"scenario": "bulk_export", "source_ip": "999.1.1.1"}, {"scenario": "bulk_export", "noise": 4},
    {"scenario": "bulk_export", "records": 0}, {"scenario": "bulk_export", "records": 10**7}, {"scenario": "bulk_export", "pace": "fast"},
    {"scenario": "bulk_export", "idempotency_key": "short"}, {"scenario": "bulk_export", "idempotency_key": "has spaces here!"},
    {"scenario": "bulk_export", "target_employee_id": 0}, {}])
def test_invalid_run_requests_are_rejected_without_side_effects(client, admin, body):
    assert client.post("/api/simulation/runs", json=body, headers=admin).status_code == 422
    assert client.get("/api/simulation/runs", headers=admin).json()["items"] == []


def test_unusable_targets_are_refused(client, admin):
    soc = employee_id(client, admin, "soc.admin")
    assert client.post("/api/simulation/runs", json={"scenario": "benign_activity", "target_employee_id": 99999}, headers=admin).status_code == 404
    assert client.post("/api/simulation/runs", json={"scenario": "benign_activity", "target_employee_id": soc}, headers=admin).status_code == 400
    bob = employee_id(client, admin, "bob.chen")
    lock = client.post("/api/containment", headers=admin, json={"employee_id": bob, "action_type": "lock_account",
                                                                "reason": "target refusal test", "confirm": True})
    assert lock.status_code == 201
    refused = client.post("/api/simulation/runs", json={"scenario": "benign_activity", "target_employee_id": bob}, headers=admin)
    assert refused.status_code == 409 and "locked" in refused.json()["detail"]
    assert client.get("/api/simulation/runs", headers=admin).json()["items"] == []


def test_scenario_catalogue_lists_eligibility_and_paces(client, admin):
    config = client.get("/api/simulation/scenarios", headers=admin).json()
    assert REQUIRED <= {s["id"] for s in config["scenarios"]} and config["paces"] == ["instant", "demo"]
    assert all(set(t["eligible"]) == {s["id"] for s in config["scenarios"]} for t in config["targets"])


# --------------------------------------------------------------------------------------------- lifecycle
@pytest.mark.parametrize("scenario", ALL)
def test_each_scenario_runs_through_the_backend_and_stores_its_metadata(client, admin, db_path, scenario):
    started = client.post("/api/simulation/runs", headers=admin, json={"scenario": scenario, "pace": "instant", "seed": 21})
    assert started.status_code == 202
    first = started.json()
    assert first["status"] in ("queued", "running", "completed") and first["seed"] == 21 and first["seed_mode"] == "fixed"
    run = wait_for_run(client, admin, first["id"])
    assert run["status"] == "completed", run["error"]
    assert run["steps_done"] == run["steps_total"] == len(run["plan"]["actions"]) == len(run["results"])
    assert run["plan_sha256"] == gen.plan_digest(run["plan"])
    assert run["parameters"]["pace"] == "instant" and run["created_at"] and run["started_at"] and run["finished_at"]
    events = _events(db_path, run["id"])
    assert len(events) == run["observed"]["events"] > 0
    assert all(e[8].get("synthetic") and e[8]["sim_run"] == run["id"] for e in events)
    assert {e[1] for e in events} >= {run["target"]["id"]}
    scenario_labels = _db(db_path, "select distinct scenario, is_synthetic from security_events where simulation_run_id=?", (run["id"],))
    assert scenario_labels == [(scenario, 1)]
    # every event went through scoring (risk assessments exist for the run's events) - the runner stored none itself
    scored = _db(db_path, "select count(distinct event_id) from risk_assessments where event_id in "
                          "(select id from security_events where simulation_run_id=?)", (run["id"],))[0][0]
    assert scored >= 1
    assert run["id"] in [r["id"] for r in client.get("/api/simulation/runs", headers=admin).json()["items"]]


def test_the_stored_plan_is_exactly_what_the_generator_produces_for_that_seed(client, admin):
    run = run_scenario(client, admin, "bulk_export", seed=77, noise=2)
    with SessionLocal() as db:
        candidates = [runs.profile_of(e) for e in runs.eligible_employees(db)]
        target = runs.profile_of(db.get(Employee, run["target"]["id"]))
    assert run["plan"] == gen.generate("bulk_export", 77, target, candidates, noise=2)


def test_a_fixed_seed_reproduces_the_same_run_and_a_random_seed_is_recorded(client, admin, db_path):
    david = employee_id(client, admin, "david.kumar")
    shapes = []
    for _ in range(2):
        run = run_scenario(client, admin, "suspicious_external_transfer", seed=3, target_employee_id=david)
        shapes.append((run["plan_sha256"], [(e[2], e[3], e[4], e[6]) for e in _events(db_path, run["id"])]))
        _reset(client, admin)
    assert shapes[0] == shapes[1] and len(shapes[0][1]) > 5

    run_a = run_scenario(client, admin, "benign_activity", target_employee_id=david)
    _reset(client, admin)
    run_b = run_scenario(client, admin, "benign_activity", target_employee_id=david)
    assert run_a["seed_mode"] == run_b["seed_mode"] == "random" and run_a["seed"] != run_b["seed"]
    assert isinstance(run_a["seed"], int) and 0 <= run_a["seed"] < 2**31
    _reset(client, admin)
    replay = run_scenario(client, admin, "benign_activity", target_employee_id=david, seed=run_a["seed"])
    assert replay["plan_sha256"] == run_a["plan_sha256"]


def test_the_target_is_chosen_by_the_seed_when_none_is_given(client, admin):
    names = set()
    for seed in range(1, 7):
        run = run_scenario(client, admin, "benign_activity", seed=seed)
        names.add(run["target"]["username"])
        _reset(client, admin)
    assert len(names) >= 3


# -------------------------------------------------------------------------------- outcomes come from the detector
def test_benign_scenarios_do_not_trigger_critical_alerts(client, admin, db_path):
    levels = {"benign_activity": set(), "benign_bulk_transfer": set()}
    for scenario in levels:
        for seed in range(1, 7):
            run = run_scenario(client, admin, scenario, seed=seed)
            assert run["status"] == "completed"
            assert run["observed"]["peak_level"] != "critical" and not run["observed"]["alert_raised"], (scenario, seed, run["observed"])
            assert not run["observed"]["investigation_ids"]
            assert _db(db_path, "select count(*) from security_alerts where is_synthetic=1")[0][0] == 0
            levels[scenario].add(run["observed"]["peak_level"])
            _reset(client, admin)
    assert levels["benign_activity"] == {"normal"}
    assert levels["benign_bulk_transfer"] <= {"normal", "suspicious"}


def test_malicious_scenarios_produce_their_expected_evidence_without_a_guaranteed_outcome(client, admin, db_path):
    seen: dict[str, list] = {}
    for scenario in ("bulk_export", "suspicious_external_transfer", "gradual_collection_staging", "removable_media",
                     "correlated_low_signals", "compromised_account_campaign"):
        for seed in range(1, 7):
            run = run_scenario(client, admin, scenario, seed=seed)
            assert run["status"] == "completed", run["error"]
            events = _events(db_path, run["id"])
            seen.setdefault(scenario, []).append((run, events))
            _reset(client, admin)

    for run, events in seen["bulk_export"]:
        big = [e for e in events if e[2] in ("data_export", "file_download") and e[4] == "success" and e[6] >= 3000]
        assert big and "large_export" in run["observed"]["rules_fired"]
    for run, events in seen["suspicious_external_transfer"]:
        transfers = [e for e in events if e[2] == "external_transfer"]
        collection = [e for e in events if e[2] == "file_download" and e[8].get("phase") == "collection"]
        assert transfers and collection and collection[0][0] < transfers[0][0]       # recorded separately, after collection
        assert all(t[3] and t[8]["destination"].endswith(".invalid") for t in transfers)
    for run, events in seen["gradual_collection_staging"]:
        collection = [e for e in events if e[8].get("phase") == "collection"]
        staging = [e for e in events if e[8].get("phase") == "staging"]
        assert len(collection) >= 4 and staging and collection[-1][0] < staging[0][0]
        assert not any(e[2] == "external_transfer" for e in events)
    for run, events in seen["removable_media"]:
        copies = [e for e in events if e[8].get("channel") == "removable_media"]
        assert copies and all(e[8]["device"].startswith("USB-SIM-") for e in copies)
        if run["variant"]["volume"] == "large":
            assert "removable_media_copy" in run["observed"]["rules_fired"]
    for run, events in seen["correlated_low_signals"]:
        mine = [e for e in events if e[1] == run["target"]["id"]]
        assert max(e[7] for e in mine) <= 25                                          # each event alone is minor
        assert run["observed"]["peak_score"] > max(e[7] for e in mine)               # the correlated picture is higher
        assert run["observed"]["peak_level"] != "normal"
    for run, events in seen["compromised_account_campaign"]:
        assert {"unfamiliar_ip"} <= set(run["observed"]["rules_fired"]) and run["observed"]["peak_level"] in ("high_risk", "critical")

    # outcomes are decided by the detector and differ between runs of one scenario; nothing forces a level
    external = {run["observed"]["peak_level"] for run, _ in seen["suspicious_external_transfer"]}
    assert len(external) >= 2
    everything = {run["observed"]["peak_level"] for runs_ in seen.values() for run, _ in runs_}
    assert len(everything) >= 3 and everything <= set(LEVELS)


def test_alerts_and_investigations_come_from_the_pipeline_and_belong_to_one_run(client, admin, db_path):
    run = None
    for seed in range(1, 12):                                     # find a seed that the detector escalates to critical
        run = run_scenario(client, admin, "compromised_account_campaign", seed=seed)
        if run["observed"]["alert_raised"]:
            break
        _reset(client, admin)
    assert run["observed"]["alert_raised"]
    inv_id = run["observed"]["investigation_ids"][0]
    assert _db(db_path, "select simulation_run_id, is_synthetic from attack_investigations where id=?", (inv_id,)) == [(run["id"], 1)]
    owners = _db(db_path, "select distinct e.simulation_run_id from investigation_evidence ie join security_events e "
                          "on e.id = ie.event_id where ie.investigation_id=?", (inv_id,))
    assert owners == [(run["id"],)]
    detail = client.get(f"/api/investigations/{inv_id}", headers=admin).json()
    assert detail["status"] == "open"


def test_a_stopped_or_finished_run_is_not_mixed_with_the_next_one(client, admin, db_path):
    david = employee_id(client, admin, "david.kumar")
    first = None
    for seed in (3, 4, 5):
        first = run_scenario(client, admin, "suspicious_external_transfer", seed=seed, target_employee_id=david)
        if first["observed"]["investigation_ids"]:
            break
        _reset(client, admin)
    assert first["observed"]["investigation_ids"]
    inv = first["observed"]["investigation_ids"][0]
    before = _db(db_path, "select updated_at, (select count(*) from investigation_evidence where investigation_id=?) "
                          "from attack_investigations where id=?", (inv, inv))

    blocked = client.post("/api/simulation/runs", headers=admin, json={
        "scenario": "benign_activity", "pace": "instant", "target_employee_id": david})
    assert blocked.status_code == 409 and "reset" in blocked.json()["detail"]

    other = employee_id(client, admin, "grace.lee")
    second = run_scenario(client, admin, "suspicious_external_transfer", seed=9, target_employee_id=other)
    assert second["status"] == "completed" and second["id"] != first["id"]
    assert _db(db_path, "select updated_at, (select count(*) from investigation_evidence where investigation_id=?) "
                        "from attack_investigations where id=?", (inv, inv)) == before
    first_events = {e[0] for e in _events(db_path, first["id"])}
    second_events = {e[0] for e in _events(db_path, second["id"])}
    assert first_events and second_events and not first_events & second_events
    assert not {e[1] for e in _events(db_path, second["id"]) if e[1] == david and e[0] in first_events}
    for run in (first, second):
        for inv_id in run["observed"]["investigation_ids"]:
            owners = _db(db_path, "select distinct e.simulation_run_id from investigation_evidence ie join security_events e "
                                  "on e.id=ie.event_id where ie.investigation_id=?", (inv_id,))
            assert owners == [(run["id"],)]


# --------------------------------------------------------------------------------------------------- controls
def test_a_repeated_submission_with_the_same_key_returns_the_same_run(client, admin, db_path):
    body = {"scenario": "benign_activity", "pace": "instant", "seed": 5, "idempotency_key": "double-click-key-1"}
    one = client.post("/api/simulation/runs", json=body, headers=admin)
    two = client.post("/api/simulation/runs", json=body, headers=admin)
    assert one.status_code == two.status_code == 202
    assert one.json()["id"] == two.json()["id"] and not one.json()["duplicate_request"] and two.json()["duplicate_request"]
    run = wait_for_run(client, admin, one.json()["id"])
    third = client.post("/api/simulation/runs", json=body, headers=admin).json()
    assert third["id"] == run["id"] and third["duplicate_request"]
    assert len(client.get("/api/simulation/runs", headers=admin).json()["items"]) == 1
    assert _db(db_path, "select count(*) from security_events where simulation_run_id=?", (run["id"],))[0][0] == run["observed"]["events"]


def test_only_one_run_can_be_active_and_it_can_be_stopped(client, admin, db_path):
    started = client.post("/api/simulation/runs", headers=admin, json={"scenario": "gradual_collection_staging", "pace": "demo",
                                                                       "seed": 8, "noise": 0})
    assert started.status_code == 202
    run_id = started.json()["id"]
    second = client.post("/api/simulation/runs", headers=admin, json={"scenario": "benign_activity", "pace": "instant"})
    assert second.status_code == 409 and "still" in second.json()["detail"]
    assert client.get("/api/simulation/status", headers=admin).json()["active_run_id"] == run_id
    # manual steps and reset are refused while a run is active
    david = employee_id(client, admin, "david.kumar")
    assert client.post("/api/simulation/steps", headers=admin, json={"target_employee_id": david, "step": "unfamiliar_login"}).status_code == 409
    assert client.post("/api/simulation/reset", headers=admin).status_code == 409

    deadline = time.time() + 30
    while time.time() < deadline and client.get(f"/api/simulation/runs/{run_id}", headers=admin).json()["steps_done"] < 2:
        time.sleep(0.1)
    live = client.get(f"/api/simulation/runs/{run_id}", headers=admin).json()
    assert live["status"] == "running" and 2 <= live["steps_done"] < live["steps_total"]

    stopped = client.post(f"/api/simulation/runs/{run_id}/cancel", headers=admin).json()
    assert stopped["status"] == "cancelled" and stopped["steps_done"] < stopped["steps_total"] and stopped["finished_at"]
    assert client.get("/api/simulation/status", headers=admin).json()["active_run_id"] is None
    assert client.get("/api/simulation/status", headers=admin).json()["active_synthetic_sessions"] == 0
    events_after_stop = _db(db_path, "select count(*) from security_events where simulation_run_id=?", (run_id,))[0][0]
    assert events_after_stop == stopped["observed"]["events"] > 0                   # evidence from the partial run is kept
    time.sleep(0.5)
    assert _db(db_path, "select count(*) from security_events where simulation_run_id=?", (run_id,))[0][0] == events_after_stop
    assert client.post(f"/api/simulation/runs/{run_id}/cancel", headers=admin).json()["status"] == "cancelled"
    assert client.post("/api/simulation/runs/99999/cancel", headers=admin).status_code == 404
    assert _db(db_path, "select count(*) from audit_logs where action in ('simulation_run_created', 'simulation_run_cancel_requested', "
                        "'simulation_run_finished')")[0][0] >= 3

    again = run_scenario(client, admin, "benign_activity", seed=1)                  # the slot is free again
    assert again["status"] == "completed"
    reset = client.post("/api/simulation/reset", headers=admin)
    assert reset.status_code == 200 and reset.json()["runs"] >= 2
    assert client.get("/api/simulation/runs", headers=admin).json()["items"] == []
    assert client.get(f"/api/simulation/runs/{run_id}", headers=admin).status_code == 404


def test_a_run_that_breaks_is_marked_failed_and_releases_the_slot(client, admin, monkeypatch):
    def boom(ctx, action):
        raise RuntimeError("simulated defect")

    monkeypatch.setitem(runs._ACTIONS, "login", boom)
    run = run_scenario(client, admin, "benign_activity", seed=2)
    assert run["status"] == "failed" and "internal error" in run["error"] and "RuntimeError" in run["error"]
    assert "simulated defect" not in run["error"] and run["steps_done"] == 0
    assert client.get("/api/simulation/status", headers=admin).json()["active_run_id"] is None
    monkeypatch.undo()
    assert run_scenario(client, admin, "benign_activity", seed=2)["status"] == "completed"


def test_runs_left_active_by_a_previous_process_are_marked_failed_on_startup(client, admin):
    with SessionLocal() as db:
        employee = db.query(Employee).filter(Employee.username == "soc.admin").one()
        stale = SimulationRun(scenario="bulk_export", seed=1, seed_mode="fixed", status="running", active_slot=1,
                              started_by_id=employee.id, plan={"actions": []})
        db.add(stale)
        db.commit()
        stale_id = stale.id
        assert runs.recover_interrupted(db) == 1
    run = client.get(f"/api/simulation/runs/{stale_id}", headers=admin).json()
    assert run["status"] == "failed" and "restarted" in run["error"]
    assert client.get("/api/simulation/status", headers=admin).json()["active_run_id"] is None


def test_containment_changes_what_a_later_run_can_do(client, admin, db_path):
    run = run_scenario(client, admin, "benign_activity", seed=4)
    target = run["target"]["id"]
    lock = client.post("/api/containment", headers=admin, json={"employee_id": target, "action_type": "lock_account",
                                                                "reason": "containment drill", "confirm": True})
    assert lock.status_code == 201
    refused = client.post("/api/simulation/runs", headers=admin, json={
        "scenario": "benign_activity", "pace": "instant", "target_employee_id": target})
    assert refused.status_code == 409 and "locked" in refused.json()["detail"]


# ---------------------------------------------------------------------------------------------------- safety
def test_no_network_connection_or_name_lookup_happens_during_a_run(client, admin, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("simulation attempted a network operation")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    run = run_scenario(client, admin, "suspicious_external_transfer", seed=3)
    assert run["status"] == "completed", run["error"]
    transfers = [r for r in run["results"] if "transfer" in r["detail"]]
    assert transfers and all("nothing is sent" in r["detail"] for r in transfers)
