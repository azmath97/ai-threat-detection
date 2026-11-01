"""SOC dashboard API: every number, row, graph node and action comes from the live backend state."""
import pytest
from conftest import auth_header

ATTACKER_IP = "185.220.101.45"
STEPS = ["unfamiliar_login", "restricted_access", "large_export", "admin_login_failures",
         "create_privileged_account", "privileged_login", "external_transfer"]


@pytest.fixture(autouse=True)
def clean(client, admin):
    yield
    client.post("/api/simulation/reset", headers=admin)


def employee_pk(client, admin, username):
    return next(e["id"] for e in client.get("/api/employees", headers=admin).json() if e["username"] == username)


def run_steps(client, admin, username, steps):
    pk = employee_pk(client, admin, username)
    return [client.post("/api/simulation/steps", headers=admin, json={
        "target_employee_id": pk, "step": s, "source_ip": ATTACKER_IP, "scenario": "it_admin_full_chain"}).json() for s in steps]


def soc(client, admin, path, **params):
    response = client.get(f"/api/soc/{path}", headers=admin, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_soc_endpoints_require_security_administrator(client):
    alice = auth_header(client, "EMP-1001")
    for path in ("version", "overview", "events", "employees", "investigations", "scopes", "response", "audit"):
        assert client.get(f"/api/soc/{path}", headers=alice).status_code == 403, path
        assert client.get(f"/api/soc/{path}").status_code == 401, path


def test_overview_kpis_come_from_the_database_and_react_to_an_attack(client, admin):
    before = soc(client, admin, "overview")
    stats = client.get("/api/dashboard/stats", headers=admin).json()
    assert before["kpis"]["total_events"] == stats["events_total"]
    assert before["kpis"]["critical_alerts"] == 0 and before["kpis"]["confirmed_external_transfers"] == 0
    assert before["thresholds"] == {"suspicious": 25, "high_risk": 50, "critical": 80}
    assert len(before["events_per_hour"]) == 24 and sum(before["employees_by_severity"].values()) == 11

    run_steps(client, admin, "david.kumar", STEPS)
    after = soc(client, admin, "overview")
    k0, k1 = before["kpis"], after["kpis"]
    assert k1["total_events"] > k0["total_events"] and k1["active_investigations"] == k0["active_investigations"] + 1
    assert k1["critical_alerts"] == 1 and k1["high_risk_employees"] == k0["high_risk_employees"] + 1
    assert k1["confirmed_external_transfers"] == 1
    assert k1["sensitive_records_accessed"] >= k0["sensitive_records_accessed"] + 25_000
    (threat,) = [t for t in after["threats"] if t["employee_id"] == "EMP-1004"]
    assert threat["level"] == "critical" and threat["confidence"] >= 80 and threat["stage"] == "exfiltration"
    assert threat["exposure_status"] == "confirmed_external_transfer" and threat["last_event_at"]["local"]
    assert threat["investigation_status"] == "open" and threat["alert_id"]
    history = soc(client, admin, "confidence-history", employee_id=threat["employee_pk"])
    scores = [h["score"] for h in history]
    assert len(scores) >= 7 and scores == sorted(scores)      # confidence only rises as related evidence arrives


def test_change_token_moves_only_when_something_happens(client, admin):
    first, second = soc(client, admin, "version"), soc(client, admin, "version")
    assert first["token"] == second["token"]
    run_steps(client, admin, "grace.lee", ["unfamiliar_login"])
    third = soc(client, admin, "version")
    assert third["token"] != first["token"] and third["events"] > first["events"]
    run_steps(client, admin, "grace.lee", ["restricted_access"])
    assert soc(client, admin, "version")["assessments"] > third["assessments"]


def test_live_feed_fields_and_filters(client, admin):
    run_steps(client, admin, "david.kumar", STEPS[:4])
    feed = soc(client, admin, "events", limit=200)
    rows = feed["rows"]
    assert [r["id"] for r in rows] == sorted((r["id"] for r in rows), reverse=True) and feed["latest_id"] == rows[0]["id"]
    row = rows[0]
    assert {"timestamp", "employee_id", "event_type", "source_ip", "resource", "outcome", "anomaly_score",
            "risk_contribution", "stage", "severity"} <= set(row)
    assert row["employee_id"] == "EMP-1004" and row["anomaly_score"] is not None and row["synthetic"]

    david = soc(client, admin, "events", employee="EMP-1004", ip=ATTACKER_IP)["rows"]
    assert david and all(r["employee_id"] == "EMP-1004" and r["source_ip"] == ATTACKER_IP for r in david)
    failed = soc(client, admin, "events", event_type="login_failed", employee="EMP-1004")["rows"]
    assert len(failed) >= 5 and all(r["event_type"] == "login_failed" for r in failed)
    assert any(r["stage"] == "credential_misuse" for r in failed)
    critical = soc(client, admin, "events", severity="critical")["rows"]
    assert critical and all(r["severity"] == "critical" for r in critical)
    assert soc(client, admin, "events", minutes=5, employee="EMP-1004")["rows"]
    assert soc(client, admin, "events", ip="203.0.113.250")["rows"] == []
    assert client.get("/api/soc/events", headers=admin, params={"severity": "bogus"}).status_code == 422


def test_investigation_list_and_detail(client, admin):
    run_steps(client, admin, "david.kumar", STEPS)
    (row,) = [r for r in soc(client, admin, "investigations") if r["employee_id"] == "EMP-1004"]
    assert row["level"] == "critical" and row["stage"] == "exfiltration" and row["status"] == "open"
    assert row["first_event"]["timestamp"]["local"] and row["latest_event"]["event_id"] > row["first_event"]["event_id"]
    assert row["exposure_status"] == "confirmed_external_transfer" and row["records_exposed"] == 25_000
    assert soc(client, admin, "investigations", status="resolved") == []
    detail = soc(client, admin, f"investigations/{row['id']}")
    assert detail["alert"]["evidence"] and detail["alert"]["trigger_event_id"] < detail["latest_event"]["event_id"]
    assert detail["live"]["components"]["rules"]["weight"] > 0 and detail["timeline"] and detail["recommended_actions"]
    assert client.get("/api/soc/investigations/99999", headers=admin).status_code == 404


def test_employee_risk_monitor_ranks_by_risk_without_personal_attributes(client, admin):
    run_steps(client, admin, "david.kumar", STEPS)
    rows = soc(client, admin, "employees")
    assert rows[0]["employee_id"] == "EMP-1004" and rows[0]["level"] == "critical"
    assert [r["risk_score"] for r in rows] == sorted((r["risk_score"] for r in rows), reverse=True)
    assert {"employee_id", "department", "job_role", "risk_score", "anomaly_score", "suspicious_events_24h",
            "last_suspicious", "investigation_status"} <= set(rows[0])
    assert rows[0]["suspicious_events_24h"] > 5 and rows[0]["investigation_status"] == "open"
    forbidden = {"name", "full_name", "email", "gender", "age", "username"}
    assert not any(forbidden & set(r) for r in rows)
    assert any(r["account_type"] == "Created during incident" for r in rows)


def test_timeline_is_built_from_correlated_events_and_marks_the_current_stage(client, admin):
    run_steps(client, admin, "david.kumar", STEPS[:5])
    (row,) = [r for r in soc(client, admin, "investigations") if r["employee_id"] == "EMP-1004"]
    partial = soc(client, admin, "timeline", investigation_id=row["id"])
    assert [s["stage"] for s in partial["stages"]] == [
        "initial_access", "credential_misuse", "sensitive_resource_access", "collection", "privilege_escalation",
        "persistence", "lateral_movement", "exfiltration"]
    reached = {s["stage"] for s in partial["stages"] if s["reached"]}
    assert {"initial_access", "credential_misuse", "collection", "persistence"} <= reached
    assert "exfiltration" not in reached and partial["current_stage"] == "persistence"
    assert [s["stage"] for s in partial["stages"] if s["current"]] == ["persistence"]

    run_steps(client, admin, "david.kumar", STEPS[5:])
    full = soc(client, admin, "timeline", investigation_id=row["id"])
    assert full["current_stage"] == "exfiltration" and [s["stage"] for s in full["stages"] if s["current"]] == ["exfiltration"]
    stamps = [e["timestamp"]["utc"] for e in full["events"]]
    assert stamps == sorted(stamps) and len(full["events"]) > len(partial["events"])
    assert all(e["event_id"] for e in full["events"]) and full["stages"][-1]["event_count"] >= 1
    live = soc(client, admin, "timeline", employee_id=row["employee_pk"])
    assert live["current_stage"] == "exfiltration" and live["events"]


def test_attack_graph_is_derived_from_event_relationships_and_grows_with_the_attack(client, admin):
    pk = employee_pk(client, admin, "david.kumar")
    run_steps(client, admin, "david.kumar", STEPS[:3])
    early = soc(client, admin, "graph", employee_id=pk)
    kinds = {n["kind"] for n in early["nodes"]}
    assert {"account", "ip", "session", "system"} <= kinds and not {"external", "privileged_account"} & kinds
    assert any(n["id"] == f"ip:{ATTACKER_IP}" and n["suspicious"] for n in early["nodes"])
    ids = {n["id"] for n in early["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in early["edges"])
    assert {"session", "origin", "access"} <= {e["kind"] for e in early["edges"]}
    assert any(e["kind"] == "access" and e["outcome"] == "denied" and "denied" in e["label"] for e in early["edges"])

    run_steps(client, admin, "david.kumar", STEPS[3:])
    late = soc(client, admin, "graph", employee_id=pk)
    assert len(late["nodes"]) > len(early["nodes"]) and late["event_count"] > early["event_count"]
    kinds = {n["kind"] for n in late["nodes"]}
    assert {"privileged_account", "external"} <= kinds
    assert {"created", "transfer"} <= {e["kind"] for e in late["edges"]}
    external = next(n for n in late["nodes"] if n["kind"] == "external")
    assert external["label"] == "files.exfil-sim.example.invalid"
    (row,) = [r for r in soc(client, admin, "investigations") if r["employee_id"] == "EMP-1004"]
    assert soc(client, admin, "graph", investigation_id=row["id"])["nodes"]


def test_response_centre_recommendations_confirmation_and_enforcement(client, admin):
    run_steps(client, admin, "david.kumar", STEPS)
    pk = employee_pk(client, admin, "david.kumar")
    centre = soc(client, admin, "response")
    (threat,) = [t for t in centre["threats"] if t["employee_pk"] == pk]
    by_action = {(a["action"], a["target"]): a for a in threat["actions"]}
    assert ("block_ip", ATTACKER_IP) in by_action and ("lock_account", "svc.backup01") in by_action
    assert ("remove_privileges", None) in by_action and ("revoke_sessions", None) in by_action
    assert {a["target"] for a in threat["actions"] if a["action"] == "isolate_system"} >= {"it-admin-console"}
    assert not any(a["done"] for a in threat["actions"])
    assert {o["action"] for o in centre["options"]} >= {"lock_account", "revoke_sessions", "block_ip", "remove_privileges",
                                                        "restrict_access", "isolate_system"}

    body = {"employee_id": pk, "action_type": "block_ip", "reason": "Attacker address", "target": ATTACKER_IP,
            "investigation_id": threat["investigation_id"]}
    refused = client.post("/api/containment", headers=admin, json=body)       # no confirmation
    assert refused.status_code == 400 and "Confirmation required" in refused.json()["detail"]
    assert not soc(client, admin, "response")["controls"]

    done = client.post("/api/containment", headers=admin, json={**body, "confirm": True})
    assert done.status_code == 201 and done.json()["details"]["ip"] == ATTACKER_IP
    assert client.post("/api/containment", headers=admin, json={**body, "confirm": True}).status_code == 409
    control = soc(client, admin, "response")["controls"][0]
    assert control["kind"] == "blocked_ip" and control["value"] == ATTACKER_IP and control["by"] == "SEC-9011"
    # enforcement: the attacker can no longer authenticate from that address and sessions were revoked
    again = run_steps(client, admin, "david.kumar", ["unfamiliar_login", "restricted_access"])
    assert [r["status"] for r in again] == ["blocked", "blocked"] and "blocked" in again[0]["detail"]

    system = {"employee_id": pk, "action_type": "isolate_system", "reason": "Targeted system", "target": "it-admin-console",
              "confirm": True}
    assert client.post("/api/containment", headers=admin, json=system).status_code == 201
    david = auth_header(client, "EMP-1004")
    denied = client.post("/api/resources/it-admin-console/access", headers=david, json={})
    assert denied.status_code == 403
    isolated_event = client.get("/api/events", headers=admin, params={"employee_id": pk, "limit": 1}).json()["items"][0]
    assert isolated_event["details"]["reason"] == "system_isolated" and isolated_event["risk_points"] == 0

    privileges = client.post("/api/containment", headers=admin, json={
        "employee_id": pk, "action_type": "remove_privileges", "reason": "Strip write access", "confirm": True})
    assert privileges.status_code == 201 and privileges.json()["details"]["downgraded"]
    after = soc(client, admin, "response")
    (threat,) = [t for t in after["threats"] if t["employee_pk"] == pk]
    done_actions = {(a["action"], a["target"]) for a in threat["actions"] if a["done"]}
    assert {("block_ip", ATTACKER_IP), ("remove_privileges", None), ("isolate_system", "it-admin-console")} <= done_actions
    assert {c["kind"] for c in after["controls"]} == {"blocked_ip", "isolated_system"}

    # release and restore are non-disruptive and need no confirmation
    for action, target in (("unblock_ip", ATTACKER_IP), ("release_system", "it-admin-console")):
        assert client.post("/api/containment", headers=admin, json={
            "employee_id": pk, "action_type": action, "reason": "Resolved", "target": target}).status_code == 201
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": pk, "action_type": "restore_account", "reason": "Resolved"}).status_code == 201
    assert not soc(client, admin, "response")["controls"]
    assert client.post("/api/resources/it-admin-console/access", headers=auth_header(client, "EMP-1004"), json={}).status_code == 200


def test_lock_related_account_through_the_incident_investigation(client, admin):
    run_steps(client, admin, "david.kumar", STEPS[:5])
    pk = employee_pk(client, admin, "svc.backup01")
    (row,) = [r for r in soc(client, admin, "investigations") if r["employee_id"] == "EMP-1004"]
    locked = client.post("/api/containment", headers=admin, json={
        "employee_id": pk, "action_type": "lock_account", "reason": "Created during incident", "confirm": True,
        "investigation_id": row["id"]})
    assert locked.status_code == 201
    assert run_steps(client, admin, "david.kumar", ["privileged_login"])[0]["status"] == "blocked"
    assert soc(client, admin, "response")["threats"]


def test_audit_trail_covers_alerts_investigations_containment_admin_and_failures(client, admin):
    run_steps(client, admin, "david.kumar", STEPS)
    pk = employee_pk(client, admin, "david.kumar")
    (row,) = [r for r in soc(client, admin, "investigations") if r["employee_id"] == "EMP-1004"]
    failed_before = len(soc(client, admin, "audit", category="failed_response")["rows"])
    client.post("/api/containment", headers=admin, json={"employee_id": pk, "action_type": "lock_account", "reason": "Contain"})
    client.post("/api/containment", headers=admin, json={"employee_id": pk, "action_type": "lock_account", "reason": "Contain",
                                                         "confirm": True})
    client.post("/api/containment", headers=admin, json={"employee_id": pk, "action_type": "lock_account", "reason": "Again",
                                                         "confirm": True})
    assert client.get(f"/api/investigations/{row['id']}/export", headers=admin).status_code == 200

    audit = soc(client, admin, "audit")
    cats = {r["category"] for r in audit["rows"]}
    assert {"alerts", "investigations", "containment", "administrator", "failed_response"} <= cats
    assert set(audit["categories"]) == {"alerts", "investigations", "containment", "administrator", "failed_response"}
    for r in audit["rows"]:
        assert r["timestamp"]["local"] and r["actor"]
    failed = soc(client, admin, "audit", category="failed_response")["rows"]
    new_failures = failed[: len(failed) - failed_before]
    assert len(new_failures) == 2 and all(r["actor"] == "SEC-9011" and r["target"] == "EMP-1004" for r in new_failures)
    assert any("Confirmation required" in r["summary"] for r in new_failures)
    assert any("already locked" in r["summary"] for r in new_failures)
    contained = soc(client, admin, "audit", category="containment")["rows"]
    assert contained[0]["action"] == "containment_lock_account" and contained[0]["actor"] == "SEC-9011"
    assert any(r["action"] == "alert_created" and r["actor"] == "SYSTEM" for r in soc(client, admin, "audit", category="alerts")["rows"])
    assert any(r["action"] == "investigation_exported" for r in soc(client, admin, "audit", category="investigations")["rows"])
    assert any(r["action"] == "simulation_step" for r in soc(client, admin, "audit", category="administrator")["rows"])


def test_simulation_reset_clears_response_controls(client, admin):
    run_steps(client, admin, "david.kumar", STEPS[:3])
    pk = employee_pk(client, admin, "david.kumar")
    (row,) = [r for r in soc(client, admin, "investigations") if r["employee_id"] == "EMP-1004"]
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": pk, "action_type": "block_ip", "reason": "Block attacker", "target": ATTACKER_IP, "confirm": True,
        "investigation_id": row["id"]}).status_code == 201
    assert soc(client, admin, "response")["controls"]
    assert client.post("/api/simulation/reset", headers=admin).status_code == 200
    assert not soc(client, admin, "response")["controls"]
    assert [r for r in soc(client, admin, "investigations") if r["employee_id"] == "EMP-1004"] == []
