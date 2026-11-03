import sqlite3

from conftest import auth_header, login, run_steps


def _employee_id(client, admin, username):
    employees = client.get("/api/employees", headers=admin).json()
    return next(e["id"] for e in employees if e["username"] == username)


def _query(db_path, sql, params=()):
    con = sqlite3.connect(db_path)
    try:
        return con.execute(sql, params).fetchall()
    finally:
        con.close()


def _events(client, admin, username, **params):
    emp = _employee_id(client, admin, username)
    return client.get("/api/events", headers=admin, params={"employee_id": emp, "limit": 500, **params}).json()["items"]


# ------------------------------------------------------------------ foundation
def test_seed_data_codes_and_password_hashing(client, admin, db_path):
    employees = client.get("/api/employees", headers=admin).json()
    assert len(employees) == 11
    assert sum(e["role"] == "employee" for e in employees) == 10
    assert {e["employee_code"] for e in employees} >= {"EMP-1001", "EMP-1010", "SEC-9011"}
    hashes = [r[0] for r in _query(db_path, "select password_hash from employees")]
    tables = {r[0] for r in _query(db_path, "select name from sqlite_master where type='table'")}
    assert all(h.startswith("$argon2id$") and "Demo2026" not in h for h in hashes)
    assert len(set(hashes)) == len(hashes)
    assert {"employees", "employee_sessions", "access_permissions", "security_events", "risk_assessments",
            "security_alerts", "attack_investigations", "containment_actions", "audit_logs"} <= tables


def test_login_by_employee_id_rbac_and_no_internal_data(client, admin):
    assert login(client, "EMP-1001", "wrong-password").status_code == 401
    assert login(client, "EMP-9999").status_code == 401
    assert client.post("/api/auth/login", json={"password": "x"}).status_code == 422
    assert client.get("/api/employees/me").status_code == 401
    alice = auth_header(client, "EMP-1001")
    me = client.get("/api/employees/me", headers=alice).json()
    assert me["employee_code"] == "EMP-1001" and me["created_at_local"] and me["previous_login_at"]
    assert me["known_ips"] == []  # detection baseline is never shown to employees
    for path in ("/api/events", "/api/dashboard/stats", "/api/alerts", "/api/investigations", "/api/simulation/scenarios"):
        assert client.get(path, headers=alice).status_code == 403, path
    assert client.post("/api/simulation/reset", headers=alice).status_code == 403
    assert client.get("/api/employees/2", headers=alice).status_code == 403
    assert client.get("/api/dashboard/stats", headers=admin).status_code == 200


def test_event_is_saved_with_all_required_fields(client, admin, db_path):
    jack = auth_header(client, "EMP-1010")
    response = client.post(
        "/api/events", headers={**jack, "X-Device-Info": "Pytest Browser/1.0"},
        json={"event_type": "resource_access", "resource": "marketing-assets", "record_count": 3,
              "details": {"note": "pytest-marker"}, "employee_id": 1, "source_ip": "6.6.6.6"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body.get("risk_score") is None and "details" not in body["event"]  # nothing sensitive for employees
    row = _query(db_path, "select employee_id, session_id, event_type, resource, outcome, source_ip, device_info, "
                          "records_accessed, records_downloaded, is_synthetic, details, timestamp "
                          "from security_events where id=?", (body["event"]["id"],))[0]
    jack_id = _employee_id(client, admin, "jack.silva")
    assert row[0] == jack_id  # client-supplied employee_id ignored
    assert row[1] is not None
    assert row[2:5] == ("resource_access", "marketing-assets", "success")
    assert row[5] == "10.20.9.101"  # client-supplied IP ignored; loopback maps to registered workstation
    assert row[6] == "Pytest Browser/1.0" and row[7] == 3 and row[8] == 0 and row[9] == 0
    assert "pytest-marker" in row[10] and row[11]


def test_validation_and_errors(client):
    jack = auth_header(client, "EMP-1010")
    assert client.post("/api/events", headers=jack, json={"event_type": "bogus"}).status_code == 422
    assert client.post("/api/events", headers=jack, json={"event_type": "resource_access"}).status_code == 422
    assert client.post("/api/events", headers=jack, json={"event_type": "logout"}).status_code == 422
    assert client.post("/api/resources/nope/access", headers=jack, json={}).status_code == 404
    assert client.get("/api/portal/payslips/2020-13", headers=jack).status_code == 404
    assert client.get("/api/portal/hr/records", headers={"Authorization": "Bearer nope"}).status_code == 401


# ------------------------------------------------------------------ portal
def test_general_employee_portal_and_event_collection(client, admin):
    alice = auth_header(client, "EMP-1001")
    slips = client.get("/api/portal/payslips", headers=alice).json()
    assert len(slips) == 6
    slip = client.get(f"/api/portal/payslips/{slips[0]['period']}", headers=alice).json()
    assert slip["employee_id"] == "EMP-1001" and slip["net"] < slip["gross"]
    assert client.get("/api/portal/profile", headers=alice).json()["employee_id"] == "EMP-1001"

    docs = client.get("/api/portal/documents", headers=alice).json()
    ids = {d["id"] for d in docs}
    assert "DOC-001" in ids and "DOC-020" in ids and "DOC-090" not in ids  # permitted documents only
    download = client.get("/api/portal/documents/DOC-020/download", headers=alice)
    assert download.status_code == 200 and "SYNTHETIC DOCUMENT" in download.text
    assert "attachment" in download.headers["content-disposition"]

    # Backend refuses everything outside the role, and logs the denial
    assert client.get("/api/portal/documents/DOC-090/download", headers=alice).status_code == 403
    assert client.get("/api/portal/hr/records", headers=alice).status_code == 403
    assert client.get("/api/portal/hr/records/EMP-1002", headers=alice).status_code == 403
    assert client.get("/api/portal/payroll/register", headers=alice).status_code == 403
    assert client.post("/api/portal/payroll/export", headers=alice).status_code == 403

    results = client.get("/api/portal/directory", headers=alice, params={"q": "kumar"}).json()
    assert [r["name"] for r in results] == ["David Kumar"]
    assert set(results[0]) == {"employee_id", "name", "department", "job_role", "email", "phone", "location"}

    events = _events(client, admin, "alice.morgan")
    by_key = {}
    for e in events:  # newest first: keep the most recent event of each kind
        by_key.setdefault((e["event_type"], e["resource"], e["outcome"]), e)
    assert ("resource_access", "my-payslips", "success") in by_key
    dl = by_key[("file_download", "financial-reports", "success")]
    assert dl["records_downloaded"] == 1 and dl["session_id"] and dl["device_info"] and dl["source_ip"] == "10.20.1.11"
    assert ("file_download", "hr-records", "denied") in by_key
    assert ("resource_access", "hr-records", "denied") in by_key
    assert ("data_export", "payroll-records", "denied") in by_key
    search = by_key[("directory_search", "employee-directory", "success")]
    assert search["records_accessed"] == 1 and search["details"]["query"] == "kumar"
    assert not any(e["is_synthetic"] for e in events)


def test_ordinary_working_session_raises_no_alert(client, admin):
    """Routine work (even outside office hours or with repeated restricted-data access) must not alert."""
    carol_id = _employee_id(client, admin, "carol.diaz")
    carol = auth_header(client, "EMP-1003")
    for _ in range(3):
        for _ in range(4):
            assert client.get("/api/portal/hr/records", headers=carol).status_code == 200
            assert client.get("/api/portal/hr/records/EMP-1002", headers=carol).status_code == 200
        assert client.get("/api/portal/payroll/register", headers=carol).status_code == 200
        assert client.get("/api/portal/payslips", headers=carol).status_code == 200
        assert client.get("/api/portal/directory", headers=carol, params={"q": "a"}).status_code == 200
    assert client.post("/api/auth/logout", headers=carol).status_code == 204
    risk = client.get(f"/api/risk/employees/{carol_id}", headers=admin).json()
    assert risk["level"] in ("normal", "suspicious"), risk
    assert client.get("/api/alerts", headers=admin, params={"employee_id": carol_id}).json() == []


def test_hr_and_payroll_roles(client, admin):
    carol = auth_header(client, "EMP-1003")  # HR manager: hr-records write, payroll read
    records = client.get("/api/portal/hr/records", headers=carol).json()
    assert len(records) == 11
    assert len(client.get("/api/portal/hr/records", headers=carol, params={"q": "finance"}).json()) == 2
    record = client.get("/api/portal/hr/records/EMP-1002", headers=carol).json()
    assert record["name"] == "Bob Chen" and "manager" in record and "emergency_contact" in record
    assert client.get("/api/portal/hr/records/EMP-0000", headers=carol).status_code == 404
    assert len(client.get("/api/portal/payroll/register", headers=carol).json()) == 11
    assert client.post("/api/portal/payroll/export", headers=carol).status_code == 403  # read-only

    bob = auth_header(client, "EMP-1002")  # payroll specialist: write
    export = client.post("/api/portal/payroll/export", headers=bob)
    assert export.status_code == 200 and export.json()["content"].startswith("employee_id,name")
    exported = [e for e in _events(client, admin, "bob.chen") if e["event_type"] == "data_export"]
    assert exported[0]["resource"] == "payroll-records" and exported[0]["records_downloaded"] == export.json()["record_count"]
    hr = _events(client, admin, "carol.diaz", event_type="resource_access")
    assert any(e["details"].get("employee_id") == "EMP-1002" and e["records_accessed"] == 1 for e in hr)


def test_session_logout_generates_events(client, admin):
    emp = "EMP-1005"
    assert login(client, emp, "wrong").status_code == 401
    response = login(client, emp)
    headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/employees/me", headers=headers).status_code == 401
    types = [e["event_type"] for e in _events(client, admin, "emma.wilson")][:3]
    assert types == ["logout", "login", "login_failed"]


# ------------------------------------------------------------------ simulation
def test_simulation_full_chain_uses_real_pipeline_and_resets(client, admin, db_path):
    david = _employee_id(client, admin, "david.kumar")
    # employee-facing responses never carry risk data (checked on a genuine session before the simulation starts)
    assert "risk" not in client.get("/api/events/me", headers=auth_header(client, "EMP-1004")).text
    base_events = _query(db_path, "select count(*) from security_events where is_synthetic=0")[0][0]
    base_alerts = _query(db_path, "select count(*) from security_alerts")[0][0]
    base_score = client.get(f"/api/risk/employees/{david}", headers=admin).json()["score"]

    config = client.get("/api/simulation/scenarios", headers=admin).json()
    assert len(config["steps"]) == 7 and any(t["username"] == "david.kumar" for t in config["targets"])
    assert len(config["scenarios"]) >= 7
    bad = {"target_employee_id": david, "source_ip": "not-an-ip", "step": "unfamiliar_login"}
    assert client.post("/api/simulation/steps", headers=admin, json=bad).status_code == 422

    steps = run_steps(client, admin, "david.kumar", [s["id"] for s in config["steps"]], ip="185.220.101.45",
                      scenario="it_admin_full_chain", records=25000)
    results = {r["step"]: r for r in steps}
    assert all(r["status"] == "completed" for r in results.values()), results
    assert "svc.backup01" in results["create_privileged_account"]["detail"]

    events = _events(client, admin, "david.kumar", synthetic="true")
    assert events and all(e["is_synthetic"] and e["scenario"] == "it_admin_full_chain" for e in events)
    assert {e["source_ip"] for e in events} == {"185.220.101.45"}
    types = {e["event_type"] for e in events}
    assert {"login", "login_failed", "resource_access", "administrative_action"} <= types
    assert any(e["records_downloaded"] == 25000 for e in events)
    # activity of the newly created account is recorded under that account, flagged synthetic
    priv = _events(client, admin, "svc.backup01")
    assert priv and all(e["is_synthetic"] for e in priv)
    assert {"login", "external_transfer"} <= {e["event_type"] for e in priv}

    # the real detection engine reacted: attack chain, critical risk, synthetic alert + investigation
    risk = client.get(f"/api/risk/employees/{david}", headers=admin).json()
    assert risk["level"] == "critical"
    assert {"initial_access", "credential_misuse", "sensitive_resource_access", "collection", "privilege_escalation",
            "persistence", "lateral_movement", "exfiltration"} <= set(risk["attack_stages"])
    alerts = client.get("/api/alerts", headers=admin, params={"employee_id": david}).json()
    assert len(alerts) == 1 and alerts[0]["severity"] == "critical"
    assert _query(db_path, "select is_synthetic from security_alerts where id=?", (alerts[0]["id"],))[0][0] == 1
    investigation = client.get(f"/api/investigations/{alerts[0]['investigation_id']}", headers=admin).json()
    assert any("svc.backup01" in i for i in investigation["indicators"])
    assert any(t["account"] == "svc.backup01" for t in investigation["timeline"])
    assert client.get("/api/simulation/status", headers=admin).json()["steps_executed"] == [s["id"] for s in config["steps"]]

    # containment applies to the simulated attacker exactly as to a real one
    lock = client.post("/api/containment", headers=admin, json={
        "employee_id": david, "action_type": "lock_account", "reason": "Simulation drill", "confirm": True})
    assert lock.status_code == 201
    blocked = client.post("/api/simulation/steps", headers=admin, json={
        "target_employee_id": david, "step": "unfamiliar_login", "source_ip": "185.220.101.45"}).json()
    assert blocked["status"] == "blocked"

    reset = client.post("/api/simulation/reset", headers=admin)
    assert reset.status_code == 200, reset.text
    assert reset.json()["accounts"] == 1 and reset.json()["employees_restored"] >= 1
    for table in ("security_events", "employee_sessions", "security_alerts", "attack_investigations"):
        assert _query(db_path, f"select count(*) from {table} where is_synthetic=1")[0][0] == 0, table
    assert _query(db_path, "select count(*) from employees where is_synthetic=1")[0][0] == 0
    assert _query(db_path, "select count(*) from security_events where is_synthetic=0")[0][0] == base_events
    assert _query(db_path, "select count(*) from security_alerts")[0][0] == base_alerts
    assert _query(db_path, "select status from employees where id=?", (david,))[0][0] == "active"
    assert client.get(f"/api/risk/employees/{david}", headers=admin).json()["score"] == base_score
    assert client.get("/api/simulation/status", headers=admin).json()["synthetic_events"] == 0


def test_simulation_standard_employee_is_limited_by_permissions(client, admin):
    henry = _employee_id(client, admin, "henry.novak")
    run = run_steps(client, admin, "henry.novak", ["unfamiliar_login", "restricted_access", "large_export",
                                                    "admin_login_failures", "external_transfer"], scenario="finance_data_theft")
    results = {r["step"]: r for r in run}
    assert "hr-records: denied" in results["restricted_access"]["detail"]
    assert results["large_export"]["status"] == "completed" and "source-code-repo" in results["large_export"]["detail"]
    assert "create_privileged_account" not in results
    denied = [e for e in _events(client, admin, "henry.novak", synthetic="true") if e["outcome"] == "denied"]
    assert len(denied) >= 4

    priv = client.post("/api/simulation/steps", headers=admin, json={
        "target_employee_id": henry, "step": "create_privileged_account"}).json()
    assert priv["status"] == "denied"
    assert client.post("/api/simulation/steps", headers=admin, json={
        "target_employee_id": henry, "step": "privileged_login"}).json()["status"] == "blocked"
    assert client.post("/api/simulation/reset", headers=admin).status_code == 200
    assert client.get("/api/simulation/status", headers=admin).json()["synthetic_events"] == 0


def test_real_account_creation_requires_admin_console_access(client, admin):
    henry = auth_header(client, "EMP-1008")
    body = {"username": "svc.test01", "full_name": "Test Service", "password": "A-long-password-1"}
    assert client.post("/api/admin/accounts", headers=henry, json=body).status_code == 403
    assert client.post("/api/admin/accounts", headers=henry, json={**body, "password": "short"}).status_code == 422
    assert any(e["event_type"] == "administrative_action" and e["outcome"] == "denied"
               for e in _events(client, admin, "henry.novak"))


# ------------------------------------------------------------------ containment
def test_restrict_and_restore_access(client, admin):
    emp_id = _employee_id(client, admin, "grace.lee")
    r = client.post("/api/containment", headers=admin, json={
        "employee_id": emp_id, "action_type": "restrict_access", "reason": "Precaution", "confirm": True})
    assert r.status_code == 201 and r.json()["details"]["removed_permissions"]
    grace = auth_header(client, "EMP-1007")
    assert client.post("/api/resources/audit-reports/access", headers=grace, json={}).status_code == 403
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": emp_id, "action_type": "restore_account", "reason": "Cleared"}).status_code == 201
    assert client.post("/api/resources/audit-reports/access", headers=grace, json={}).status_code == 200


def test_admin_cannot_contain_self_and_unknown_action(client, admin):
    me = client.get("/api/employees/me", headers=admin).json()
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": me["id"], "action_type": "lock_account", "reason": "oops", "confirm": True}).status_code == 400
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": me["id"], "action_type": "nuke", "reason": "oops"}).status_code == 422


def test_dashboard_stats_and_investigation_run(client, admin):
    stats = client.get("/api/dashboard/stats", headers=admin).json()
    assert stats["total_employees"] == 11 and stats["events_total"] > 100
    assert len(stats["events_per_hour_24h"]) == 24
    assert client.get("/api/risk/employees", headers=admin).status_code == 200
    emp_id = _employee_id(client, admin, "isla.murphy")
    assert client.post("/api/investigations", headers=admin, json={"employee_id": emp_id}).status_code == 201
    assert client.post("/api/risk/assess", headers=admin, json={"employee_id": emp_id}).status_code == 200
    assert client.get("/api/investigations/999999", headers=admin).status_code == 404
