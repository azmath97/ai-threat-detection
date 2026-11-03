"""The five detection states: what switches each one on, and that model output is never shown as confirmed."""
from backend import detection_states as ds
from conftest import auth_header  # noqa: F401  (fixtures are provided by conftest)


def _active(states):
    return {s["state"] for s in states if s["active"]}


def test_state_vocabulary_is_fixed_and_labelled():
    assert ds.STATE_ORDER == ("anomalous_activity", "suspicious_sequence", "potential_data_exposure", "confirmed_ground_truth",
                              "containment_completed")
    assert set(ds.STATE_LABELS) == set(ds.STATE_DEFINITIONS) == set(ds.STATE_ORDER)
    assert "Confirmed" in ds.STATE_LABELS["confirmed_ground_truth"] and "simulation ground truth" in ds.STATE_LABELS["confirmed_ground_truth"]
    assert "never" in ds.STATE_DEFINITIONS["confirmed_ground_truth"].lower()


def test_model_outputs_alone_never_make_activity_confirmed():
    everything_but_ground_truth = ds.derive(anomaly_score=1.0, independent_stages=6, exposure_status="confirmed_external_transfer",
                                            ground_truth_simulation=False, containment_actions=0)
    assert _active(everything_but_ground_truth) == {"anomalous_activity", "suspicious_sequence", "potential_data_exposure"}
    by_state = {s["state"]: s for s in everything_but_ground_truth}
    assert "no ground truth exists for live activity" in by_state["confirmed_ground_truth"]["basis"]
    assert "verified" in by_state["potential_data_exposure"]["basis"]          # the event is verified; the exposure stays 'potential'


def test_each_state_has_its_own_condition():
    quiet = ds.derive(anomaly_score=0.1, independent_stages=0, exposure_status="none", ground_truth_simulation=False, containment_actions=0)
    assert _active(quiet) == set()
    assert _active(ds.derive(anomaly_score=0.5, independent_stages=1, exposure_status="none", ground_truth_simulation=False,
                             containment_actions=0)) == {"anomalous_activity"}
    assert _active(ds.derive(anomaly_score=0.0, independent_stages=2, exposure_status="none", ground_truth_simulation=False,
                             containment_actions=0)) == {"suspicious_sequence"}
    suspicious = ds.derive(anomaly_score=0.0, independent_stages=1, exposure_status="suspicious_access", ground_truth_simulation=False,
                           containment_actions=0)
    assert _active(suspicious) == {"potential_data_exposure"}
    assert "no verified export" in {s["state"]: s for s in suspicious}["potential_data_exposure"]["basis"]
    assert _active(ds.derive(anomaly_score=0.0, independent_stages=0, exposure_status="none", ground_truth_simulation=True,
                             containment_actions=0)) == {"confirmed_ground_truth"}
    assert _active(ds.derive(anomaly_score=0.0, independent_stages=0, exposure_status="none", ground_truth_simulation=False,
                             containment_actions=1)) == {"containment_completed"}


def test_states_and_audit_follow_a_simulated_attack_through_containment(client, admin):
    employees = client.get("/api/employees", headers=admin).json()
    david = next(e["id"] for e in employees if e["username"] == "david.kumar")
    from conftest import run_steps

    from backend.simulation_service import STEP_IDS

    done = run_steps(client, admin, "david.kumar", STEP_IDS, records=8000)
    assert all(r["status"] == "completed" for r in done)
    threats = client.get("/api/soc/overview", headers=admin).json()["threats"]
    row = next(t for t in threats if t["employee_id"] == "EMP-1004")
    states = {s["state"]: s for s in row["states"]}
    assert [s["state"] for s in row["states"]] == list(ds.STATE_ORDER)
    assert states["suspicious_sequence"]["active"] and states["potential_data_exposure"]["active"]
    assert states["confirmed_ground_truth"]["active"] and "simulated" in states["confirmed_ground_truth"]["basis"]
    assert not states["containment_completed"]["active"]

    investigation = row["investigation_id"]
    assert investigation
    detail = client.get(f"/api/soc/investigations/{investigation}", headers=admin).json()
    assert [s["state"] for s in detail["states"]] == list(ds.STATE_ORDER) and detail["state_definitions"]
    audit = detail["audit"]
    assert {c["component"] for c in audit["components"]} == {"ml", "rules", "correlation", "baseline", "stage"}
    assert abs(sum(c["contribution"] for c in audit["components"]) - audit["confidence"]) < 1.0 or audit["capped_by_stage_count"]
    assert audit["reason_codes"] and all({"rule", "points", "description"} <= set(r) for r in audit["reason_codes"])
    assert audit["evidence"] and all(e["event_id"] and e["timestamp"] for e in audit["evidence"])
    assert "not statistically independent" in audit["note"]

    done = client.post("/api/containment", headers=admin, json={"employee_id": david, "action_type": "revoke_sessions",
                                                                "reason": "state check", "confirm": True,
                                                                "investigation_id": investigation})
    assert done.status_code in (200, 201)
    after = client.get(f"/api/soc/investigations/{investigation}", headers=admin).json()
    assert {s["state"]: s["active"] for s in after["states"]}["containment_completed"]
