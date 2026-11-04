"""End-to-end integration: employee actions -> backend events -> detection -> SOC read models -> investigation -> containment.

Everything goes through the real HTTP API and the one SQLite database (no service-level shortcuts).
"""
import sqlite3
from datetime import datetime, timedelta

import pytest
from conftest import app_now, auth_header, login
from fastapi.testclient import TestClient

from backend.main import app

ATTACKER_IP = "185.220.101.45"
NEW_IP = "203.0.113.9"
SCENARIO = "it_admin_full_chain"
STEPS = ["unfamiliar_login", "restricted_access", "large_export", "admin_login_failures",
         "create_privileged_account", "privileged_login", "external_transfer"]


def pk_of(client, admin, username):
    return next(e["id"] for e in client.get("/api/employees", headers=admin).json() if e["username"] == username)


def events_of(client, admin, pk, **params):
    return client.get("/api/events", headers=admin, params={"employee_id": pk, "limit": 500, **params}).json()["items"]


def parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ---------------------------------------------------------------- normal employee
def test_normal_employee_session_is_recorded_by_the_soc_and_stays_low_risk(client, admin, db_path):
    pk = pk_of(client, admin, "alice.morgan")
    started = app_now() - timedelta(seconds=2)

    response = login(client, "EMP-1001")                                    # familiar (registered workstation) address
    assert response.status_code == 200
    token = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert client.get("/api/employees/me", headers=token).json()["employee_code"] == "EMP-1001"
    assert client.get("/api/portal/profile", headers=token).status_code == 200
    documents = client.get("/api/portal/documents", headers=token).json()
    assert documents, "a general employee has permitted documents"
    assert client.get(f"/api/portal/documents/{documents[0]['id']}/download", headers=token).status_code == 200
    slips = client.get("/api/portal/payslips", headers=token).json()
    assert client.get(f"/api/portal/payslips/{slips[0]['period']}", headers=token).status_code == 200
    assert client.post("/api/auth/logout", headers=token).status_code == 204
    assert client.get("/api/employees/me", headers=token).status_code == 401      # the session really ended

    events = [e for e in events_of(client, admin, pk) if parse(e["timestamp"]) >= started]
    kinds = [(e["event_type"], e["resource"]) for e in sorted(events, key=lambda e: e["id"])]
    assert kinds[0] == ("login", None) and kinds[-1] == ("logout", None)
    assert {("resource_access", "my-profile"), ("file_download", documents[0]["resource"]),
            ("resource_access", "my-payslips")} <= set(kinds)
    assert all(e["outcome"] == "success" and e["is_synthetic"] is False and e["risk_points"] < 25 for e in events), \
        [(e["event_type"], e["risk_points"], e["risk_flags"]) for e in events]
    assert len({e["session_id"] for e in events}) == 1 and None not in {e["session_id"] for e in events}
    assert {e["source_ip"] for e in events} == {"10.20.1.11"}                # the backend set the IP, not the client
    assert all(started <= parse(e["timestamp"]) <= app_now() + timedelta(seconds=2) for e in events)

    # the SOC reads the same rows from the same database
    feed = client.get("/api/soc/events", headers=admin, params={"employee": "EMP-1001", "limit": 100}).json()
    feed_ids = {r["id"] for r in feed["rows"]}
    assert {e["id"] for e in events} <= feed_ids
    with sqlite3.connect(db_path) as con:
        stored = {r[0] for r in con.execute("select id from security_events where employee_id=?", (pk,))}
    assert {e["id"] for e in events} <= stored

    risk = client.get(f"/api/risk/employees/{pk}", headers=admin).json()
    assert risk["score"] < 25 and risk["level"] == "normal"
    assert [a for a in client.get("/api/alerts", headers=admin).json() if a["employee_username"] == "alice.morgan"] == []
    soc_row = next(r for r in client.get("/api/soc/employees", headers=admin).json() if r["employee_id"] == "EMP-1001")
    assert soc_row["risk_score"] < 25 and soc_row["investigation_id"] is None


# ---------------------------------------------------------------- compromised account
def test_compromised_account_is_detected_correlated_and_alerted_before_the_external_transfer(client, admin, db_path):
    pk = pk_of(client, admin, "david.kumar")
    confidence, results, alerted_after = [], {}, None

    def step(name):
        nonlocal alerted_after
        out = client.post("/api/simulation/steps", headers=admin, json={
            "target_employee_id": pk, "step": name, "source_ip": ATTACKER_IP, "scenario": SCENARIO, "records": 8000}).json()
        results[name] = out
        assert out["status"] == "completed", out
        assert out["event_ids"], f"{name} recorded no events"
        threats = [t for t in client.get("/api/soc/overview", headers=admin).json()["threats"] if t["employee_id"] == "EMP-1004"]
        confidence.append(threats[0]["risk_score"] if threats else 0.0)
        if alerted_after is None and any(a["risk_band"] == "critical" for a in client.get("/api/alerts", headers=admin).json()
                                          if a["employee_username"] == "david.kumar"):
            alerted_after = name
        return out

    for name in STEPS:
        step(name)

    # 1. every step's events are stored, synthetic-flagged and attributed to the right account
    stored = {e["id"]: e for e in events_of(client, admin, pk)}
    svc_pk = pk_of(client, admin, "svc.backup01")
    stored.update({e["id"]: e for e in events_of(client, admin, svc_pk)})
    for name, out in results.items():
        assert set(out["event_ids"]) <= set(stored), name
        assert all(stored[i]["is_synthetic"] and stored[i]["source_ip"] == ATTACKER_IP for i in out["event_ids"])
    kinds = {n: [stored[i]["event_type"] for i in out["event_ids"]] for n, out in results.items()}
    assert kinds["unfamiliar_login"] == ["login"] and kinds["admin_login_failures"] == ["login_failed"] * 5
    assert set(kinds["restricted_access"]) == {"resource_access"} and len(kinds["restricted_access"]) == 5
    probed = {stored[i]["resource"]: stored[i]["outcome"] for i in results["restricted_access"]["event_ids"]}
    assert "payroll-records" in probed and "it-admin-console" in probed       # restricted payroll and the IT admin portal
    assert probed["payroll-records"] == "denied"                                # the backend permission model decided

    # 2. detection: the 8,000-record export is flagged, and the final transfer is a separate event
    (export_id,) = results["large_export"]["event_ids"]
    (transfer_id,) = results["external_transfer"]["event_ids"]
    export, transfer = stored[export_id], stored[transfer_id]
    assert export["event_type"] in ("data_export", "file_download") and export["records_downloaded"] == 8000
    assert any(f["rule"] == "large_export" for f in export["risk_flags"])
    assert transfer["event_type"] == "external_transfer" and transfer["id"] != export["id"]
    assert transfer["details"]["transfer_status"] == "confirmed" and transfer["records_downloaded"] == 8000
    assert any(f["rule"] == "unfamiliar_ip" for f in stored[results["unfamiliar_login"]["event_ids"][0]]["risk_flags"])
    assert any(f["rule"] == "admin_console_login_failed" for i in results["admin_login_failures"]["event_ids"]
               for f in stored[i]["risk_flags"])
    created = [stored[i] for i in results["create_privileged_account"]["event_ids"]]
    assert any(f["rule"] == "privileged_account_created" for e in created for f in e["risk_flags"])
    assert stored[results["privileged_login"]["event_ids"][0]]["employee_username"] == "svc.backup01"

    # 3. the confidence score rises as related evidence arrives and never exceeds 100
    assert confidence == sorted(confidence) and confidence[0] < confidence[-1] <= 100
    assert confidence[0] < 50 and confidence[-1] >= 80

    # 4. early detection: critical alert BEFORE the external transfer
    assert alerted_after is not None and STEPS.index(alerted_after) < STEPS.index("external_transfer")
    (alert,) = [a for a in client.get("/api/alerts", headers=admin).json() if a["employee_username"] == "david.kumar"]
    assert alert["risk_band"] == "critical" and alert["investigation_id"] and alert["first_event_id"]
    assert alert["detected_at"] < transfer["timestamp"] and alert["event_id"] < transfer["id"]

    # 5. exposure keeps the export and the confirmed transfer apart
    exposure = client.get(f"/api/risk/employees/{pk}", headers=admin).json()["exposure"]
    assert exposure["status"] == "confirmed_external_transfer" and exposure["external_transfer_confirmed"]
    assert exposure["records_exported"] == 8000 and exposure["records_confirmed_external"] == 8000
    assert exposure["records_potentially_exposed"] == 8000                      # same records, not counted twice

    # 6. correlation + investigation hold the evidence; the SOC shows timeline and recommendations
    inv = client.get(f"/api/soc/investigations/{alert['investigation_id']}", headers=admin).json()
    case_ids = set(inv["case_file"]["event_ids"])
    flagged = {i for out in results.values() for i in out["event_ids"] if stored[i]["risk_flags"]}
    assert flagged <= case_ids and {export_id, transfer_id} <= case_ids
    related = {r for e in client.get(f"/api/investigations/{inv['id']}/evidence", headers=admin).json()["events"] for r in e["relations"]}
    assert related >= {"flagged", "session", "ip", "related_account"} and {r for ev in inv["alert"]["evidence"] for r in ev["relations"]} >= {"session", "ip"}
    assert inv["integrity"]["intact"] and inv["stage"] == "exfiltration" and inv["attack_type"] == "confirmed_external_transfer"
    timeline = client.get("/api/soc/timeline", headers=admin, params={"investigation_id": inv["id"]}).json()
    reached = {s["stage"] for s in timeline["stages"] if s["reached"]}
    assert {"initial_access", "credential_misuse", "sensitive_resource_access", "collection", "privilege_escalation",
            "persistence", "exfiltration"} <= reached
    assert timeline["current_stage"] == "exfiltration" and len(timeline["events"]) >= 12
    graph = client.get("/api/soc/graph", headers=admin, params={"investigation_id": inv["id"]}).json()
    assert {n["kind"] for n in graph["nodes"]} >= {"account", "ip", "session", "system", "external"}
    actions = {(a["action"], a["target"]) for a in inv["recommended_actions"]}
    assert {("revoke_sessions", None), ("block_ip", ATTACKER_IP), ("lock_account", "svc.backup01"),
            ("remove_privileges", None), ("isolate_system", "it-admin-console")} <= actions
    feed = client.get("/api/soc/events", headers=admin, params={"ip": ATTACKER_IP, "limit": 200}).json()["rows"]
    assert {export_id, transfer_id} <= {r["id"] for r in feed}
    assert any(r["risk_contribution"] > 0 and r["stage"] for r in feed)

    # 7. containment changes the simulated environment
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": pk, "action_type": "block_ip", "target": ATTACKER_IP, "reason": "Integration check",
        "confirm": True, "investigation_id": inv["id"]}).status_code == 201
    blocked = client.post("/api/simulation/steps", headers=admin, json={
        "target_employee_id": pk, "step": "unfamiliar_login", "source_ip": ATTACKER_IP, "scenario": SCENARIO}).json()
    assert blocked["status"] == "blocked"
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": pk, "action_type": "lock_account", "reason": "Integration check", "confirm": True}).status_code == 201
    assert login(client, "EMP-1004").status_code == 403


# ---------------------------------------------------------------- false positive
def test_new_ip_and_permitted_resource_is_recognised_but_not_a_critical_attack(client, admin):
    pk = pk_of(client, admin, "isla.murphy")
    traveller = TestClient(app, client=(NEW_IP, 50000))                         # a real HTTP peer on an unfamiliar address
    response = login(traveller, "EMP-1009")
    assert response.status_code == 200
    token = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert traveller.post("/api/resources/loan-applications/access", headers=token, json={"action": "view", "record_count": 5}).status_code == 200

    events = [e for e in events_of(client, admin, pk) if e["source_ip"] == NEW_IP]
    assert {e["event_type"] for e in events} >= {"login", "resource_access"}
    assert any(f["rule"] == "unfamiliar_ip" for e in events for f in e["risk_flags"])      # the unusual IP is recognised
    risk = client.get(f"/api/risk/employees/{pk}", headers=admin).json()
    assert risk["level"] in ("normal", "suspicious") and risk["score"] < 50
    assert risk["current_stage"] == "initial_access"
    assert [a for a in client.get("/api/alerts", headers=admin).json() if a["employee_username"] == "isla.murphy"] == []
    assert not [r for r in client.get("/api/soc/investigations", headers=admin).json() if r["employee_id"] == "EMP-1009"]
    traveller.post("/api/auth/logout", headers=token)


# ---------------------------------------------------------------- live updates and persistence of the shared state
def test_soc_change_token_moves_when_an_employee_acts(client, admin):
    before = client.get("/api/soc/version", headers=admin).json()["token"]
    assert client.get("/api/soc/version", headers=admin).json()["token"] == before        # idle: nothing changes
    auth_header(client, "EMP-1002")                                                  # a login is an event
    after = client.get("/api/soc/version", headers=admin).json()
    assert after["token"] != before and after["events"] > int(before.split("|")[0])
