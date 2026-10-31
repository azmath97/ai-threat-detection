import sqlite3

from conftest import auth_header, login


def _employee_id(client, admin, username):
    employees = client.get("/api/employees", headers=admin).json()
    return next(e["id"] for e in employees if e["username"] == username)


def test_seed_data_and_password_hashing(client, admin, db_path):
    employees = client.get("/api/employees", headers=admin).json()
    assert len(employees) == 11
    assert sum(e["role"] == "employee" for e in employees) == 10
    con = sqlite3.connect(db_path)
    hashes = [r[0] for r in con.execute("select password_hash from employees")]
    tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
    con.close()
    assert all(h.startswith("pbkdf2_sha256$") and "Demo2026" not in h for h in hashes)
    assert len(set(hashes)) == len(hashes)  # unique salts
    assert {"employees", "employee_sessions", "access_permissions", "security_events", "risk_assessments",
            "security_alerts", "attack_investigations", "containment_actions", "audit_logs"} <= tables


def test_auth_and_rbac(client, admin):
    assert login(client, "alice.morgan", "wrong-password").status_code == 401
    assert login(client, "nobody.here").status_code == 401
    assert client.get("/api/employees/me").status_code == 401
    alice = auth_header(client, "alice.morgan")
    me = client.get("/api/employees/me", headers=alice).json()
    assert me["username"] == "alice.morgan" and me["created_at_local"]
    assert client.get("/api/events", headers=alice).status_code == 403
    assert client.get("/api/dashboard/stats", headers=alice).status_code == 403
    assert client.get("/api/employees/2", headers=alice).status_code == 403
    assert client.get(f"/api/employees/{me['id']}", headers=alice).status_code == 200
    assert client.get("/api/dashboard/stats", headers=admin).status_code == 200


def test_event_is_saved_to_sqlite(client, admin, db_path):
    jack = auth_header(client, "jack.silva", ip="10.20.9.101")
    response = client.post("/api/events", headers=jack, json={
        "event_type": "resource_access", "resource": "marketing-assets", "details": {"note": "pytest-marker"}})
    assert response.status_code == 201, response.text
    event_id = response.json()["event"]["id"]
    assert "risk_score" not in response.json() or response.json()["risk_score"] is None  # employees never see risk

    con = sqlite3.connect(db_path)
    row = con.execute(
        "select event_type, resource, outcome, source_ip, details from security_events where id=?", (event_id,)
    ).fetchone()
    assessments = con.execute("select count(*) from risk_assessments where event_id=?", (event_id,)).fetchone()[0]
    con.close()
    assert row[:3] == ("resource_access", "marketing-assets", "success")
    assert "pytest-marker" in row[4]
    assert assessments == 1

    stored = client.get("/api/events", headers=admin, params={"employee_id": _employee_id(client, admin, "jack.silva")}).json()
    assert any(e["id"] == event_id for e in stored["items"])


def test_validation_and_errors(client):
    jack = auth_header(client, "jack.silva")
    assert client.post("/api/events", headers=jack, json={"event_type": "bogus"}).status_code == 422
    assert client.post("/api/events", headers=jack, json={"event_type": "resource_access"}).status_code == 422
    assert client.post("/api/events", headers=jack, json={"event_type": "logout"}).status_code == 403
    assert client.post("/api/events", headers=jack, json={"event_type": "external_transfer", "source_ip": "not-an-ip"}).status_code == 422
    assert client.post("/api/resources/nope/access", headers=jack, json={}).status_code == 404


def test_denied_access_is_403_and_logged(client, admin):
    jack = auth_header(client, "jack.silva")
    assert client.post("/api/resources/hr-records/access", headers=jack, json={"action": "view"}).status_code == 403
    events = client.get("/api/events", headers=admin, params={
        "employee_id": _employee_id(client, admin, "jack.silva"), "outcome": "denied"}).json()
    assert any(e["resource"] == "hr-records" and "access_denied" in {f["rule"] for f in e["risk_flags"]} for e in events["items"])


def test_attack_chain_alert_investigation_and_containment(client, admin):
    victim = "frank.osei"
    victim_id = _employee_id(client, admin, victim)
    evil_ip = "198.51.100.77"
    for _ in range(3):
        assert login(client, victim, "guess", ip=evil_ip).status_code == 401
    headers = auth_header(client, victim, ip=evil_ip)
    for resource in ("payroll-records", "hr-records", "it-admin-console"):
        assert client.post(f"/api/resources/{resource}/access", headers=headers, json={"action": "view"}).status_code == 403
    assert client.post("/api/resources/customer-accounts/access", headers=headers,
                       json={"action": "download", "record_count": 5000}).status_code == 200
    assert client.post("/api/resources/customer-accounts/access", headers=headers,
                       json={"action": "export", "record_count": 5000}).status_code == 200

    risk = client.get(f"/api/risk/employees/{victim_id}", headers=admin).json()
    assert risk["level"] == "critical" and risk["score"] >= 75
    assert {"initial_access", "discovery", "collection", "exfiltration"} <= set(risk["attack_stages"])

    alerts = client.get("/api/alerts", headers=admin, params={"employee_id": victim_id, "status": "open"}).json()
    assert len(alerts) == 1 and alerts[0]["severity"] == "critical"
    investigation = client.get(f"/api/investigations/{alerts[0]['investigation_id']}", headers=admin).json()
    assert investigation["attack_stage"] == "exfiltration" and investigation["timeline"] and investigation["indicators"]
    assert {a["action"] for a in investigation["recommended_actions"]} >= {"revoke_sessions", "lock_account"}

    action = client.post("/api/containment", headers=admin, json={
        "employee_id": victim_id, "action_type": "lock_account", "reason": "Compromised credentials",
        "investigation_id": investigation["id"]})
    assert action.status_code == 201 and action.json()["details"]["sessions_revoked"] >= 1
    assert client.get("/api/employees/me", headers=headers).status_code in (401, 403)
    assert login(client, victim, ip=evil_ip).status_code == 403
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": victim_id, "action_type": "lock_account", "reason": "again"}).status_code == 409
    assert client.get(f"/api/investigations/{investigation['id']}", headers=admin).json()["status"] == "contained"
    assert client.get("/api/alerts", headers=admin, params={"employee_id": victim_id}).json()[0]["status"] == "contained"

    restore = client.post("/api/containment", headers=admin, json={
        "employee_id": victim_id, "action_type": "restore_account", "reason": "Identity verified"})
    assert restore.status_code == 201
    assert login(client, victim).status_code == 200


def test_restrict_and_restore_access(client, admin):
    emp_id = _employee_id(client, admin, "grace.lee")
    r = client.post("/api/containment", headers=admin, json={
        "employee_id": emp_id, "action_type": "restrict_access", "reason": "Precaution"})
    assert r.status_code == 201 and r.json()["details"]["removed_permissions"]
    grace = auth_header(client, "grace.lee")
    assert client.post("/api/resources/audit-reports/access", headers=grace, json={}).status_code == 403
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": emp_id, "action_type": "restore_account", "reason": "Cleared"}).status_code == 201
    assert client.post("/api/resources/audit-reports/access", headers=grace, json={}).status_code == 200


def test_admin_cannot_contain_self_and_unknown_action(client, admin):
    me = client.get("/api/employees/me", headers=admin).json()
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": me["id"], "action_type": "lock_account", "reason": "oops"}).status_code == 400
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": me["id"], "action_type": "nuke", "reason": "oops"}).status_code == 422


def test_dashboard_stats_and_investigation_run(client, admin):
    stats = client.get("/api/dashboard/stats", headers=admin).json()
    assert stats["total_employees"] == 11 and stats["events_total"] > 100
    assert len(stats["events_per_hour_24h"]) == 24
    assert client.get("/api/risk/employees", headers=admin).status_code == 200
    emp_id = _employee_id(client, admin, "henry.novak")
    assert client.post("/api/investigations", headers=admin, json={"employee_id": emp_id}).status_code == 201
    assert client.post("/api/risk/assess", headers=admin, json={"employee_id": emp_id}).status_code == 200
    assert client.get("/api/investigations/999999", headers=admin).status_code == 404
