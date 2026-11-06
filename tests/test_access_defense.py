"""Unauthorised access defence, tested with real requests: the backend refuses (401/403) and the refusals are monitored.

The refusals themselves are enforced by the existing authorisation code; these tests check that repeated refusals become
incidents with evidence, that probing is told apart from repetition, that extreme patterns end the account's sessions, and that
the monitoring cannot be used to flood the database or to punish normal behaviour."""
import sqlite3

from conftest import auth_header
from test_auth_defense import KEY, KNOWN, WRONG, actions, bearer, db_read, incidents, manual, signin, status_of

from backend.database import engine
from backend.models import AccessDenial


def calls(client, headers, method, path, times=1, ip=None):
    extra = {"X-Frontend-Key": KEY, "X-Client-IP": ip} if ip else {}
    return [client.request(method, path, headers={**headers, **extra}) for _ in range(times)]


def employee_pks(client, admin) -> dict[str, int]:
    return {e["employee_code"]: e["id"] for e in client.get("/api/employees", headers=admin).json()}


def kinds(client, admin, **params) -> dict[str, dict]:
    return {i["kind"]: i for i in incidents(client, admin, **params)}


# ----------------------------------------------------------------------------------------- what is (and is not) recorded
def test_refused_requests_are_recorded_with_the_route_template_and_never_the_token(client, admin):
    pks = employee_pks(client, admin)
    token = bearer(signin(client, "EMP-1003", None, KNOWN["EMP-1003"]))
    assert calls(client, token, "GET", f"/api/employees/{pks['EMP-1001']}")[0].status_code == 403
    assert calls(client, {}, "GET", "/api/employees/me")[0].status_code == 401
    rows = client.get("/api/soc/auth/denials", headers=admin).json()["rows"]
    forbidden = next(r for r in rows if r["status_code"] == 403)
    assert forbidden["route"] == "/api/employees/{employee_id}" and forbidden["object"] == str(pks["EMP-1001"])
    assert forbidden["account"] == "EMP-1003" and forbidden["method"] == "GET"
    assert {r["status_code"] for r in rows} == {401, 403}
    con = sqlite3.connect(engine.url.database)
    dump = " ".join(str(v) for row in con.execute("select * from access_denials") for v in row)
    con.close()
    assert token["Authorization"].split()[-1] not in dump and "Bearer" not in dump


def test_normal_use_sign_in_failures_and_not_found_are_not_recorded_as_refusals(client, admin):
    token = bearer(signin(client, "EMP-1003", None, KNOWN["EMP-1003"]))
    assert calls(client, token, "GET", "/api/employees/me")[0].status_code == 200
    assert signin(client, "EMP-1003", WRONG, "203.0.113.200").status_code == 401           # a failed sign-in has its own record
    assert calls(client, token, "GET", "/api/no/such/route")[0].status_code == 404
    assert client.get("/api/soc/auth/denials", headers=admin).json()["rows"] == []
    assert incidents(client, admin, status="active") == [] or all(i["kind"] == "login_after_failures" for i in incidents(client, admin))


def test_a_few_refusals_raise_nothing(client, admin):
    token = bearer(signin(client, "EMP-1003", None, KNOWN["EMP-1003"]))
    calls(client, token, "GET", "/api/soc/overview", times=9)
    assert db_read(lambda db: db.query(AccessDenial).count()) == 9 and incidents(client, admin) == []


def test_the_soc_denial_feed_requires_a_security_administrator(client, admin):
    employee = auth_header(client, "EMP-1003")
    assert client.get("/api/soc/auth/denials").status_code == 401
    assert client.get("/api/soc/auth/denials", headers=employee).status_code == 403
    assert client.get("/api/soc/auth/denials", headers=admin, params={"status": 999}).status_code == 422
    assert client.get("/api/soc/auth/denials", headers=admin).status_code == 200


# ------------------------------------------------------------------------------------------------ repeated refusals
def test_repeated_refusals_raise_an_alert_and_an_extreme_pattern_ends_the_session_and_locks_the_account(client, admin):
    token = bearer(signin(client, "EMP-1003", None, KNOWN["EMP-1003"]))
    calls(client, token, "GET", "/api/soc/overview", times=10)
    incident = kinds(client, admin)["repeated_forbidden_access"]
    assert incident["severity"] == "high_risk" and incident["employee_id"] == "EMP-1003" and incident["actions"] == 0
    assert status_of("EMP-1003") == "active"                                                  # an alert, not yet a lock
    detail = client.get(f"/api/soc/auth/incidents/{incident['id']}", headers=admin).json()
    assert detail["evidence"]["refusals"] == 10 and detail["evidence"]["routes"] == ["/api/soc/overview"]
    assert len(detail["denials"]) == 10 and detail["attempts"] == [] and "refused" in detail["explanation"]

    calls(client, token, "GET", "/api/soc/overview", times=20)
    incident = kinds(client, admin)["repeated_forbidden_access"]
    assert incident["severity"] == "critical" and status_of("EMP-1003") == "locked"
    assert calls(client, token, "GET", "/api/employees/me")[0].status_code == 401             # the session was revoked
    history = client.get(f"/api/soc/auth/incidents/{incident['id']}", headers=admin).json()["response_history"]
    assert [a["action"] for a in history] == ["revoke_sessions", "lock_account"] and {a["status"] for a in history} == {"completed"}


def test_refusals_caused_by_our_own_enforcement_are_not_counted_again(client, admin):
    token = bearer(signin(client, "EMP-1003", None, KNOWN["EMP-1003"]))
    manual(client, admin, action="lock_account", target="EMP-1003", reason="locked for this test", confirm=True)
    calls(client, token, "GET", "/api/employees/me", times=40)                                # revoked token of a locked account
    assert db_read(lambda db: db.query(AccessDenial).count()) == 0 and incidents(client, admin) == []


# ------------------------------------------------------------------------------------------------------------ IDOR
def test_probing_many_records_through_one_route_is_an_idor_probe_not_a_plain_repetition(client, admin):
    pks = employee_pks(client, admin)
    token = bearer(signin(client, "EMP-1003", None, KNOWN["EMP-1003"]))
    others = [pk for code, pk in pks.items() if code != "EMP-1003"]
    for pk in others[:5]:
        assert calls(client, token, "GET", f"/api/employees/{pk}")[0].status_code == 403
    found = kinds(client, admin)
    assert found["idor_probe"]["severity"] == "high_risk" and status_of("EMP-1003") == "active"
    detail = client.get(f"/api/soc/auth/incidents/{found['idor_probe']['id']}", headers=admin).json()
    assert detail["evidence"]["distinct_objects"] == 5 and detail["evidence"]["route"] == "/api/employees/{employee_id}"
    assert set(detail["evidence"]["objects"]) == {str(pk) for pk in others[:5]}
    assert "no data was returned" in detail["explanation"]

    for pk in others[5:10]:
        calls(client, token, "GET", f"/api/employees/{pk}")
    found = kinds(client, admin)
    assert found["idor_probe"]["severity"] == "critical" and status_of("EMP-1003") == "locked"
    assert "repeated_forbidden_access" not in found                                           # the same refusals are not reported twice
    assert [a["action"] for a in client.get(f"/api/soc/auth/incidents/{found['idor_probe']['id']}", headers=admin).json()["response_history"]] \
        == ["revoke_sessions", "lock_account"]


def test_repeating_one_forbidden_object_is_not_an_idor_probe(client, admin):
    pks = employee_pks(client, admin)
    token = bearer(signin(client, "EMP-1003", None, KNOWN["EMP-1003"]))
    calls(client, token, "GET", f"/api/employees/{pks['EMP-1001']}", times=12)
    found = kinds(client, admin)
    assert "idor_probe" not in found and found["repeated_forbidden_access"]["severity"] == "high_risk"


def test_other_users_records_are_never_returned_and_the_owner_can_still_read_their_own(client, admin):
    pks = employee_pks(client, admin)
    token = bearer(signin(client, "EMP-1003", None, KNOWN["EMP-1003"]))
    refused = calls(client, token, "GET", f"/api/employees/{pks['EMP-1001']}")[0]
    assert refused.status_code == 403 and "Alice" not in refused.text and "alice" not in refused.text.lower()
    assert calls(client, token, "GET", f"/api/employees/{pks['EMP-1003']}")[0].status_code == 200


# ---------------------------------------------------------------------------------------------- unauthenticated flood
def test_a_flood_of_unauthenticated_requests_is_an_alert_and_then_a_block(client, admin):
    attacker = "198.51.100.140"
    calls(client, {}, "GET", "/api/employees/me", times=30, ip=attacker)
    incident = kinds(client, admin)["unauthenticated_flood"]
    assert incident["severity"] == "high_risk" and incident["source_ip"] == attacker
    assert [a for a in actions(client, admin) if a["action"] == "block_ip"] == []             # an alert first
    calls(client, {}, "GET", "/api/employees/me", times=70, ip=attacker)
    incident = kinds(client, admin)["unauthenticated_flood"]
    assert incident["severity"] == "critical" and incident["status"] == "contained"
    (block,) = [a for a in actions(client, admin) if a["action"] == "block_ip"]
    assert block["status"] == "completed" and block["target"] == attacker and "not a firewall rule" in block["result"]
    assert signin(client, "EMP-1001", None, attacker).status_code == 403                      # now refused as a blocked address
    assert signin(client, "EMP-1001", None, "203.0.113.141").status_code == 200


def test_unauthenticated_requests_from_a_private_address_never_cause_a_block(client, admin):
    calls(client, {}, "GET", "/api/employees/me", times=110, ip="10.77.0.9")
    assert kinds(client, admin)["unauthenticated_flood"]["severity"] == "critical"
    skipped = [a for a in actions(client, admin) if a["action"] == "block_ip"]
    assert [a["status"] for a in skipped] == ["skipped"] and "private" in skipped[0]["result"]


# --------------------------------------------------------------------------------------------- limits and modes
def test_the_per_address_cap_keeps_a_flood_of_refusals_from_filling_the_database(client, admin, monkeypatch):
    monkeypatch.setenv("DENIAL_RECORD_LIMIT_PER_MINUTE", "5")
    calls(client, {}, "GET", "/api/employees/me", times=40, ip="198.51.100.141")
    assert db_read(lambda db: db.query(AccessDenial).count()) == 5


def test_detect_only_mode_raises_the_incident_but_changes_nothing(client, admin, monkeypatch):
    monkeypatch.setenv("AUTH_AUTO_RESPONSE", "false")
    token = bearer(signin(client, "EMP-1003", None, KNOWN["EMP-1003"]))
    calls(client, token, "GET", "/api/soc/overview", times=32)
    assert kinds(client, admin)["repeated_forbidden_access"]["severity"] == "critical"
    assert status_of("EMP-1003") == "active" and actions(client, admin) == []


def test_thresholds_are_configurable(client, admin, monkeypatch):
    monkeypatch.setenv("FORBIDDEN_ALERT", "3")
    token = bearer(signin(client, "EMP-1003", None, KNOWN["EMP-1003"]))
    calls(client, token, "GET", "/api/soc/overview", times=3)
    assert kinds(client, admin)["repeated_forbidden_access"]["severity"] == "high_risk"


def test_security_administrators_are_exempt_from_the_automatic_lock(client, admin):
    from backend import auth_response
    from backend.database import SessionLocal
    from backend.models import Employee

    with SessionLocal() as db:
        employee = db.query(Employee).filter(Employee.employee_code == "SEC-9011").one()
        row = auth_response.lock_account(db, employee, reason="extreme refusal pattern", automatic=True, policy_name="idor_probe", minutes=15)
        db.commit()
    assert row is not None and row.status == "skipped" and "never locked automatically" in row.result
    assert status_of("SEC-9011") == "active" and client.get("/api/soc/auth/overview", headers=admin).status_code == 200
