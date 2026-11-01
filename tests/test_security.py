"""Security and reliability checks that apply to every endpoint, derived from the application's own route table."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from conftest import auth_header, login
from fastapi.routing import APIRoute

from backend.config import get_settings
from backend.detection_engine import level_for
from backend.main import app
from backend.security import get_auth, hash_password, require_admin, verify_password
from data.demo_accounts import DEMO_PASSWORDS

PUBLIC = {("GET", "/api/health"), ("POST", "/api/auth/login")}
SKIP_FUZZ = {"/api/detection/retrain", "/api/auth/logout"}        # retraining is slow; logout would end the shared session



def _calls(dependant):
    for dep in dependant.dependencies:
        yield dep.call
        yield from _calls(dep)


def _api_routes(candidates):
    """All APIRoute objects, including those of included routers (FastAPI >= 0.16x wraps them in _IncludedRouter)."""
    for route in candidates:
        if isinstance(route, APIRoute):
            yield route
        elif getattr(route, "original_router", None) is not None:
            yield from _api_routes(route.original_router.routes)


def routes():
    for route in _api_routes(app.routes):
        if route.path.startswith("/api"):
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                calls = set(_calls(route.dependant))
                yield method, route.path, route, (require_admin in calls), (get_auth in calls or require_admin in calls)


ROUTES = list(routes())


def fill(path: str, value: str = "1") -> str:
    out = path
    while "{" in out:
        start = out.index("{")
        out = out[:start] + value + out[out.index("}") + 1:]
    return out


# ---------------------------------------------------------------- passwords and sessions
def test_passwords_are_salted_hashes_and_sessions_store_only_a_digest(client, db_path):
    token = auth_header(client, "EMP-1001")["Authorization"].split()[-1]
    with sqlite3.connect(db_path) as con:
        hashes = [r[0] for r in con.execute("select password_hash from employees where is_synthetic = 0")]
        session_hashes = [r[0] for r in con.execute("select token_hash from employee_sessions")]
    assert len(hashes) >= 11 and len(set(hashes)) == len(hashes)
    assert len(set(DEMO_PASSWORDS.values())) == len(DEMO_PASSWORDS) == 11             # every account has its own password
    for stored in hashes:
        assert stored.startswith("pbkdf2_sha256$") and not any(p in stored for p in DEMO_PASSWORDS.values())
    assert token not in session_hashes and all(len(h) == 64 for h in session_hashes)
    assert verify_password("Correct#Horse1", hash_password("Correct#Horse1", 1000))
    assert not verify_password("wrong", hash_password("Correct#Horse1", 1000))
    assert not verify_password("anything", "plaintext-or-garbage")
    assert login(client, "EMP-1002", DEMO_PASSWORDS["alice.morgan"]).status_code == 401        # not interchangeable
    body = login(client, "EMP-1001").text
    assert "pbkdf2" not in body and DEMO_PASSWORDS["alice.morgan"] not in body
    assert "pbkdf2" not in client.get("/api/employees", headers=auth_header(client, "SEC-9011")).text


def test_wrong_credentials_are_rejected_and_recorded_without_revealing_which_part_was_wrong(client, admin):
    unknown = client.post("/api/auth/login", json={"employee_id": "EMP-9999", "password": "x" * 12})
    wrong = client.post("/api/auth/login", json={"employee_id": "EMP-1006", "password": "Wrong#Password1"})
    assert unknown.status_code == wrong.status_code == 401 and unknown.json() == wrong.json()
    assert client.post("/api/auth/login", json={"employee_id": "EMP-1006"}).status_code == 422
    assert client.post("/api/auth/login", content="not json", headers={"content-type": "application/json"}).status_code == 422
    failed = client.get("/api/events", headers=admin, params={"event_type": "login_failed", "limit": 5}).json()["items"]
    assert failed and failed[0]["outcome"] in ("failure", "denied")


# ---------------------------------------------------------------- authentication and role-based access
def test_every_endpoint_requires_authentication_except_health_and_login():
    public = {(m, p) for m, p, _, _, authed in ROUTES if not authed}
    assert public == PUBLIC, public ^ PUBLIC


@pytest.mark.parametrize("method,path", sorted({(m, p) for m, p, _, _, authed in ROUTES if authed}))
def test_protected_endpoints_reject_missing_and_invalid_tokens(client, method, path):
    url = fill(path)
    assert client.request(method, url).status_code == 401
    assert client.request(method, url, headers={"Authorization": "Bearer not-a-real-token"}).status_code == 401
    assert client.request(method, url, headers={"Authorization": "Basic abc"}).status_code == 401


def test_admin_only_endpoints_reject_employees_and_accept_security_admins(client, admin):
    employee = auth_header(client, "EMP-1001")
    admin_routes = [(m, p) for m, p, _, is_admin, _ in ROUTES if is_admin]
    assert len(admin_routes) >= 30
    for method, path in admin_routes:
        response = client.request(method, fill(path), headers=employee, json={} if method != "GET" else None)
        assert response.status_code == 403, (method, path, response.status_code)
    assert client.get("/api/soc/version", headers=admin).status_code == 200


def test_employees_cannot_read_other_employees_restricted_records(client, admin):
    alice = auth_header(client, "EMP-1001")                                  # finance analyst: no HR/payroll-staff access
    for path in ("/api/portal/hr/records", "/api/portal/hr/records/EMP-1003", "/api/portal/payroll/register"):
        assert client.get(path, headers=alice).status_code == 403, path
    assert client.post("/api/portal/payroll/export", headers=alice).status_code == 403
    assert client.get("/api/employees/2", headers=alice).status_code == 403          # another employee's profile
    assert client.get("/api/employees", headers=alice).status_code == 403
    assert client.post("/api/resources/hr-records/access", headers=alice, json={"action": "view", "record_count": 5}).status_code == 403
    assert client.get("/api/portal/payslips/1999-01", headers=alice).status_code == 404
    mine = client.get("/api/portal/payslips", headers=alice).json()
    assert mine and client.get(f"/api/portal/payslips/{mine[0]['period']}", headers=alice).json()["employee_id"] == "EMP-1001"
    # the refusals were recorded as denied events against the real caller
    denied = [e for e in client.get("/api/events", headers=admin, params={"outcome": "denied", "limit": 50}).json()["items"]
             if e["employee_username"] == "alice.morgan" and e["resource"] in ("hr-records", "payroll-records")]
    assert denied and all(e["records_accessed"] == 0 for e in denied)


def test_client_cannot_choose_identity_ip_or_privileges(client, admin):
    alice = auth_header(client, "EMP-1001")
    forged = client.post("/api/events", headers={**alice, "X-Forwarded-For": "8.8.8.8"}, json={
        "event_type": "resource_access", "resource": "internal-wiki", "employee_id": 2, "source_ip": "8.8.8.8",
        "outcome": "success", "request_id": "forge-attempt-1"})
    assert forged.status_code in (201, 422)
    mine = client.get("/api/events", headers=admin, params={"employee_id": 1, "limit": 20}).json()["items"]
    assert all(e["source_ip"] != "8.8.8.8" for e in mine)
    other = client.get("/api/events", headers=admin, params={"employee_id": 2, "limit": 20}).json()["items"]
    assert all(e["source_ip"] != "8.8.8.8" for e in other)
    assert client.post("/api/containment", headers=alice, json={
        "employee_id": 2, "action_type": "lock_account", "reason": "malicious", "confirm": True}).status_code == 403


# ---------------------------------------------------------------- invalid requests are handled safely
BAD_PATH_VALUES = ["abc", "0", "-1", "99999999999999999999", "' OR 1=1 --", "%00", "a" * 300, "../../etc/passwd"]
BAD_BODIES = [{}, [], "text", 123, None, {"x": "A" * 50_000}, {"employee_id": "' OR 1=1 --", "reason": "x" * 3, "action_type": 5},
              {"limit": -1, "reason": "ab"}]


@pytest.mark.parametrize("who", ["admin", "employee"])
def test_invalid_input_never_causes_a_server_error(client, who):
    token = auth_header(client, "SEC-9011" if who == "admin" else "EMP-1001")
    failures = []
    for method, path, route, _, authed in ROUTES:
        if path in SKIP_FUZZ or not authed:
            continue
        for value in (BAD_PATH_VALUES if "{" in path else ["1"]):
            url = fill(path, value)
            attempts = [client.request(method, url, headers=token)]
            if method != "GET":
                attempts += [client.request(method, url, headers=token, json=b) for b in BAD_BODIES]
                attempts.append(client.request(method, url, headers=token, content="{broken", headers_extra=None)
                                if False else client.request(method, url, headers={**token, "content-type": "application/json"},
                                                             content=b"{broken"))
            else:
                attempts += [client.request(method, url, headers=token, params={"limit": "-5", "q": "' OR 1=1 --", "since": "yesterday",
                                                                                 "employee_id": "abc", "offset": "9" * 30})]
            failures += [(method, path, value, r.status_code) for r in attempts if r.status_code >= 500]
    assert not failures, failures[:10]


def test_errors_use_consistent_json_and_hide_internals(client, admin):
    for url in ("/api/investigations/abc", "/api/soc/investigations/999999", "/api/employees/999999", "/api/nope"):
        response = client.get(url, headers=admin)
        assert response.status_code in (404, 422) and "detail" in response.json()
        assert "Traceback" not in response.text and "sqlalchemy" not in response.text.lower()
    huge = client.get("/api/events", headers=admin, params={"limit": 100000})
    assert huge.status_code == 422


# ---------------------------------------------------------------- audit trail
def test_audit_log_records_authentication_and_administrator_actions(client, admin):
    before = client.get("/api/audit-logs", headers=admin, params={"limit": 500}).json()
    last_id = max((r["id"] for r in before), default=0)
    token = auth_header(client, "EMP-1002")
    client.post("/api/auth/logout", headers=token)
    client.post("/api/containment", headers=token, json={"employee_id": 3, "action_type": "lock_account", "reason": "nope", "confirm": True})
    client.post("/api/containment", headers=admin, json={"employee_id": 3, "action_type": "lock_account", "reason": "no confirm"})
    new = [r for r in client.get("/api/audit-logs", headers=admin, params={"limit": 500}).json() if r["id"] > last_id]
    actions = {r["action"] for r in new}
    assert {"login_success", "logout", "containment_failed"} <= actions
    assert not any(r["action"] == "containment_lock_account" for r in new)            # the unauthorised attempt did nothing
    failed = next(r for r in new if r["action"] == "containment_failed")
    admin_id = next(e["id"] for e in client.get("/api/employees", headers=admin).json() if e["username"] == "soc.admin")
    assert failed["actor_id"] == admin_id and "Confirmation required" in failed["details"]["error"]
    ts = datetime.fromisoformat(failed["timestamp"].replace("Z", "+00:00"))
    assert abs(datetime.now(timezone.utc) - ts) < timedelta(seconds=30)
    assert [r["id"] for r in new] == sorted((r["id"] for r in new), reverse=True)


# ---------------------------------------------------------------- timestamps and score arithmetic
def test_timestamps_are_stored_in_utc_and_displayed_in_the_configured_zone(client, admin, db_path):
    from zoneinfo import ZoneInfo

    token = auth_header(client, "EMP-1003")
    now = datetime.now(timezone.utc)
    client.post("/api/resources/internal-wiki/access", headers=token, json={"action": "view", "record_count": 1})
    event = client.get("/api/events", headers=admin, params={"employee_id": 3, "limit": 1}).json()["items"][0]
    utc = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    local = datetime.fromisoformat(event["timestamp_local"])
    assert abs(utc - now) < timedelta(seconds=30) and utc.utcoffset() == timedelta(0)
    assert local == utc and local.utcoffset() == utc.astimezone(ZoneInfo(get_settings().display_timezone)).utcoffset()
    with sqlite3.connect(db_path) as con:
        raw = con.execute("select timestamp from security_events where id=?", (event["id"],)).fetchone()[0]
    assert datetime.fromisoformat(raw).replace(tzinfo=timezone.utc) == utc          # persisted as naive UTC


def test_risk_scores_are_bounded_and_levels_follow_the_configured_thresholds(client, admin):
    s = get_settings()
    for score in range(0, 101):
        expected = ("critical" if score >= s.threat_critical_threshold else "high_risk" if score >= s.threat_high_threshold
                    else "suspicious" if score >= s.threat_suspicious_threshold else "normal")
        assert level_for(score) == expected, score
    rows = client.get("/api/risk/employees", headers=admin).json()
    assert rows and all(0 <= r["score"] <= 100 for r in rows)
    assert all(r["level"] == level_for(r["score"]) for r in rows), [(r["username"], r["score"], r["level"]) for r in rows]
    detail = client.get(f"/api/risk/employees/{rows[0]['employee_id']}", headers=admin).json()
    weights = sum(c["weight"] for k, c in detail["components"].items() if isinstance(c, dict) and "weight" in c)
    assert weights == pytest.approx(1.0, abs=0.01) or not detail["components"]
    assert json.dumps(detail)                                                       # serialisable, no NaN/inf
