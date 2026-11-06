"""Authentication defence, tested through the real sign-in endpoint (no simulation, no fabricated events).

Source addresses are presented the way the dashboards present them: X-Frontend-Key plus X-Client-IP (see
backend.security.resolve_ip). The in-memory login throttle is reset before each attempt so these tests exercise the stored-attempt
detectors and the response policy; one test checks that the throttle itself still answers 429.
"""
import ipaddress
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from conftest import auth_header
from sqlalchemy import create_engine, inspect, select

from backend import auth_response, controls, migrations
from backend.database import SessionLocal, engine, utcnow
from backend.models import AuthAttempt, AuthIncident, Employee, EmployeeSession, IpBlock, ResponseAction
from backend.rate_limit import reset_all
from data.demo_accounts import demo_password

KEY = "test-frontend-key-0123456789abcdef"      # set as TRUSTED_FRONTEND_KEY by conftest
KNOWN = {"EMP-1001": "10.20.1.11", "EMP-1002": "10.20.1.21", "EMP-1003": "10.20.2.31", "SEC-9011": "10.20.10.5"}
WRONG = "not-the-password-0000"


def signin(client, who: str, password: str | None, ip: str, *, throttle_reset: bool = True):
    if throttle_reset:
        reset_all()
    return client.post("/api/auth/login", json={"employee_id": who, "password": password or demo_password(who)},
                       headers={"X-Frontend-Key": KEY, "X-Client-IP": ip})


def fail(client, who: str, ip: str, times: int = 1):
    return [signin(client, who, WRONG, ip) for _ in range(times)]


def bearer(response) -> dict:
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def db_read(fn):
    with SessionLocal() as db:
        return fn(db)


def status_of(code: str) -> str:
    return db_read(lambda db: db.scalar(select(Employee.status).where(Employee.employee_code == code)))


def incidents(client, admin, **params) -> list[dict]:
    return client.get("/api/soc/auth/incidents", headers=admin, params={"status": "all", **params}).json()["rows"]


def actions(client, admin) -> list[dict]:
    return client.get("/api/soc/auth/actions", headers=admin, params={"limit": 500}).json()["rows"]


def manual(client, admin, **body):
    return client.post("/api/soc/auth/actions", headers=admin, json=body)


# --------------------------------------------------------------------------------------------------- recording attempts
def test_every_real_attempt_is_recorded_and_unknown_usernames_are_stored_only_as_a_keyed_hash(client, admin):
    typed = "mistyped-Secret-pw-123"
    assert signin(client, typed, WRONG, "203.0.113.10").status_code == 401
    assert signin(client, "EMP-1001", WRONG, "203.0.113.10").status_code == 401
    assert signin(client, "EMP-1001", None, KNOWN["EMP-1001"]).status_code == 200
    rows = client.get("/api/soc/auth/attempts", headers=admin).json()["rows"]
    by_account = {r["account"]: r for r in rows}
    assert by_account["EMP-1001"]["source_ip"] in ("203.0.113.10", KNOWN["EMP-1001"])
    unknown = next(r for r in rows if r["account"].startswith("unknown:"))
    assert unknown["outcome"] == "failure" and unknown["reason"] == "unknown_identifier" and typed not in unknown["account"]
    assert {r["outcome"] for r in rows} == {"failure", "success"}
    # neither the typed text nor any password is stored anywhere in the attempt table or the audit log
    con = sqlite3.connect(engine.url.database)
    dump = " ".join(str(v) for t in ("auth_attempts", "audit_logs") for row in con.execute(f"select * from {t}") for v in row)
    con.close()
    assert typed not in dump and WRONG not in dump


# ------------------------------------------------------------------------------------------------------- brute force
def test_five_failures_lock_the_account_revoke_its_sessions_and_refuse_further_use(client, admin):
    token = bearer(signin(client, "EMP-1001", None, KNOWN["EMP-1001"]))
    assert client.get("/api/employees/me", headers=token).status_code == 200
    attacker = "203.0.113.20"
    assert {r.status_code for r in fail(client, "EMP-1001", attacker, 4)} == {401}
    assert status_of("EMP-1001") == "active"                                   # below the threshold
    assert fail(client, "EMP-1001", attacker)[0].status_code == 401             # the answer to the attacker does not reveal the lock
    assert status_of("EMP-1001") == "locked"

    assert client.get("/api/employees/me", headers=token).status_code == 401    # the existing session was revoked
    refused = signin(client, "EMP-1001", None, KNOWN["EMP-1001"])               # even the right password is refused
    assert refused.status_code == 403 and "locked" in refused.json()["detail"].lower()

    (incident,) = [i for i in incidents(client, admin) if i["kind"] == "account_brute_force"]
    assert incident["employee_id"] == "EMP-1001" and incident["severity"] == "suspicious" and incident["status"] == "contained"
    detail = client.get(f"/api/soc/auth/incidents/{incident['id']}", headers=admin).json()
    assert detail["evidence"]["failures"] == 5 and detail["evidence"]["threshold"] == 5 and detail["evidence"]["window_minutes"] == 5
    assert "not a probability" in detail["severity_note"] and len(detail["attempts"]) == 5
    (lock,) = [a for a in detail["response_history"] if a["action"] == "lock_account"]
    assert lock["status"] == "completed" and lock["automatic"] and lock["policy"] == "account_brute_force"
    assert lock["expires_at"]["utc"] and "revoked" in lock["result"] and "firewall rule" in lock["scope"].lower()
    overview = client.get("/api/soc/auth/overview", headers=admin).json()
    assert [a["employee_id"] for a in overview["locked_accounts"]] == ["EMP-1001"] and overview["locked_accounts"][0]["automatic"]
    assert overview["attempts"]["failure"] == 5 and overview["active_incidents"]["total"] >= 1


def test_an_automatic_lock_expires_but_revoked_sessions_never_come_back(client, admin):
    old = bearer(signin(client, "EMP-1002", None, KNOWN["EMP-1002"]))
    fail(client, "EMP-1002", "203.0.113.21", 5)
    assert status_of("EMP-1002") == "locked"
    con = sqlite3.connect(engine.url.database)
    con.execute("update employees set lock_expires_at = ? where employee_code = 'EMP-1002'", ((utcnow() - timedelta(minutes=1)).isoformat(sep=" "),))
    con.commit()
    con.close()
    fresh = signin(client, "EMP-1002", None, KNOWN["EMP-1002"])
    assert fresh.status_code == 200 and status_of("EMP-1002") == "active"
    assert client.get("/api/employees/me", headers=old).status_code == 401           # the old session stays revoked
    assert client.get("/api/employees/me", headers=bearer(fresh)).status_code == 200
    assert any(a["action"] == "unlock_account" and a["automatic"] and a["policy"] == "lock_expiry" for a in actions(client, admin))


def test_failures_from_the_accounts_own_registered_address_need_a_higher_threshold(client, admin):
    fail(client, "EMP-1003", KNOWN["EMP-1003"], 9)
    assert status_of("EMP-1003") == "active" and not [i for i in incidents(client, admin) if i["kind"] == "account_brute_force"]
    fail(client, "EMP-1003", KNOWN["EMP-1003"])
    assert status_of("EMP-1003") == "locked"
    (incident,) = [i for i in incidents(client, admin) if i["kind"] == "account_brute_force"]
    detail = client.get(f"/api/soc/auth/incidents/{incident['id']}", headers=admin).json()
    assert detail["evidence"]["all_from_known_ips"] is True and detail["evidence"]["threshold"] == 10


def test_thresholds_are_configurable(client, admin, monkeypatch):
    monkeypatch.setenv("ACCOUNT_LOCKOUT_THRESHOLD", "3")
    fail(client, "EMP-1001", "203.0.113.22", 3)
    assert status_of("EMP-1001") == "locked"


def test_the_existing_login_throttle_still_answers_429(client):
    reset_all()
    codes = [signin(client, "EMP-1001", WRONG, "203.0.113.23", throttle_reset=False).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


# --------------------------------------------------------------------------------------------- credential stuffing
def test_credential_stuffing_is_detected_and_the_address_is_blocked_in_the_application(client, admin):
    attacker = "198.51.100.77"
    victims = ["EMP-1004", "EMP-1005", "EMP-1006", "EMP-1007", "EMP-1008"]
    for who in victims:
        fail(client, who, attacker)
    (stuffing,) = [i for i in incidents(client, admin) if i["kind"] == "credential_stuffing"]
    assert stuffing["severity"] == "high_risk" and stuffing["source_ip"] == attacker
    assert not db_read(lambda db: controls.is_ip_blocked(db, attacker))           # alert first, no block yet
    assert all(status_of(w) == "active" for w in victims)                         # one failure each is not an attack on the account

    for who in ["EMP-1009", "EMP-1010", "ghost.one", "ghost.two", "ghost.three"]:
        fail(client, who, attacker)
    (stuffing,) = [i for i in incidents(client, admin) if i["kind"] == "credential_stuffing"]
    assert stuffing["severity"] == "critical" and stuffing["status"] == "contained"
    detail = client.get(f"/api/soc/auth/incidents/{stuffing['id']}", headers=admin).json()
    assert detail["evidence"]["distinct_accounts"] == 10 and detail["evidence"]["failures"] == 10
    (block,) = [a for a in detail["response_history"] if a["action"] == "block_ip"]
    assert block["status"] == "completed" and block["automatic"] and "not a firewall rule" in block["result"]
    assert db_read(lambda db: controls.is_ip_blocked(db, attacker))

    refused = signin(client, "EMP-1004", None, attacker)                          # the right password, from the blocked address
    assert refused.status_code == 403 and "blocked" in refused.json()["detail"].lower()
    assert signin(client, "EMP-1004", None, "203.0.113.99").status_code == 200    # the same account from elsewhere is unaffected
    overview = client.get("/api/soc/auth/overview", headers=admin).json()
    assert [b["ip"] for b in overview["blocked_addresses"]] == [attacker] and "not a firewall" in overview["blocked_addresses"][0]["status"]
    assert overview["attempts"]["denied"] == 1


def test_a_sustained_burst_from_one_address_is_high_risk_then_critical_and_blocked(client, admin):
    attacker = "203.0.113.30"
    for i in range(10):
        fail(client, ["EMP-1005", "EMP-1006"][i % 2], attacker)
    (burst,) = [i for i in incidents(client, admin) if i["kind"] == "ip_failure_burst"]
    assert burst["severity"] == "high_risk" and not db_read(lambda db: controls.is_ip_blocked(db, attacker))
    for i in range(10):
        fail(client, ["EMP-1005", "EMP-1006"][i % 2], attacker)
    (burst,) = [i for i in incidents(client, admin) if i["kind"] == "ip_failure_burst"]
    assert burst["severity"] == "critical" and db_read(lambda db: controls.is_ip_blocked(db, attacker))


def test_private_loopback_and_protected_addresses_are_never_blocked(client, admin, monkeypatch):
    monkeypatch.setenv("PROTECTED_IPS", "198.51.100.0/24")
    for attacker in ("10.99.0.5", "198.51.100.8", "127.0.0.1"):
        for i in range(10):
            fail(client, f"nobody{i}", attacker)
        assert not db_read(lambda db, ip=attacker: controls.is_ip_blocked(db, ip))
    skipped = [a for a in actions(client, admin) if a["action"] == "block_ip"]
    assert {a["target"] for a in skipped} == {"10.99.0.5", "198.51.100.8", "127.0.0.1"} and {a["status"] for a in skipped} == {"skipped"}
    assert any("PROTECTED_IPS" in a["result"] for a in skipped) and any("private" in a["result"] for a in skipped)
    assert db_read(lambda db: db.query(IpBlock).count()) == 0


# ------------------------------------------------------------------------------------------ takeover and recovery
def test_success_after_failures_from_an_unfamiliar_address_denies_the_session_and_contains_the_account(client, admin):
    old = bearer(signin(client, "EMP-1002", None, KNOWN["EMP-1002"]))
    attacker = "203.0.113.60"
    assert {r.status_code for r in fail(client, "EMP-1002", attacker, 3)} == {401}
    taken = signin(client, "EMP-1002", None, attacker)                              # the attacker guessed the password
    assert taken.status_code == 403 and "access_token" not in taken.text
    assert status_of("EMP-1002") == "locked" and db_read(lambda db: controls.is_ip_blocked(db, attacker))
    assert client.get("/api/employees/me", headers=old).status_code == 401

    (incident,) = [i for i in incidents(client, admin) if i["kind"] == "login_after_failures"]
    assert incident["severity"] == "critical"
    history = client.get(f"/api/soc/auth/incidents/{incident['id']}", headers=admin).json()["response_history"]
    assert [a["action"] for a in history] == ["revoke_sessions", "lock_account", "block_ip"] and {a["status"] for a in history} == {"completed"}

    # recovery: an administrator unlocks the account and removes the block; the revoked session does not come back
    assert manual(client, admin, action="unlock_account", target="EMP-1002", reason="owner verified by phone").json()["status"] == "completed"
    assert manual(client, admin, action="unblock_ip", target=attacker, reason="test address released", confirm=False).json()["status"] == "completed"
    assert status_of("EMP-1002") == "active" and not db_read(lambda db: controls.is_ip_blocked(db, attacker))
    assert client.get("/api/employees/me", headers=old).status_code == 401
    assert client.get("/api/employees/me", headers=bearer(signin(client, "EMP-1002", None, KNOWN["EMP-1002"]))).status_code == 200


def test_success_after_failures_from_the_accounts_own_address_is_flagged_but_not_acted_on(client, admin):
    fail(client, "EMP-1002", KNOWN["EMP-1002"], 3)
    ok = signin(client, "EMP-1002", None, KNOWN["EMP-1002"])
    assert ok.status_code == 200 and status_of("EMP-1002") == "active"
    (incident,) = [i for i in incidents(client, admin) if i["kind"] == "login_after_failures"]
    assert incident["severity"] == "suspicious" and incident["actions"] == 0 and "mistyped" in client.get(
        f"/api/soc/auth/incidents/{incident['id']}", headers=admin).json()["explanation"]


def test_one_account_attacked_from_several_addresses_is_detected(client, admin):
    for ip in ("203.0.113.71", "203.0.113.72", "203.0.113.73"):
        fail(client, "EMP-1005", ip, 2)
    kinds = {i["kind"] for i in incidents(client, admin)}
    assert "distributed_account_attack" in kinds
    distributed = next(i for i in incidents(client, admin) if i["kind"] == "distributed_account_attack")
    assert distributed["severity"] == "high_risk" and status_of("EMP-1005") == "locked"


# ---------------------------------------------------------------------------------------------------- safeguards
def test_security_administrators_are_never_locked_automatically(client, admin):
    fail(client, "SEC-9011", "203.0.113.80", 5)
    assert status_of("SEC-9011") == "active"
    skipped = [a for a in actions(client, admin) if a["action"] == "lock_account" and a["target"] == "SEC-9011"]
    assert [a["status"] for a in skipped] == ["skipped"] and "never locked automatically" in skipped[0]["result"]
    assert [i["status"] for i in incidents(client, admin) if i["kind"] == "account_brute_force"] == ["open"]   # left for a human


def test_detect_only_mode_raises_incidents_without_changing_anything(client, admin, monkeypatch):
    monkeypatch.setenv("AUTH_AUTO_RESPONSE", "false")
    fail(client, "EMP-1003", "203.0.113.81", 5)
    assert status_of("EMP-1003") == "active" and actions(client, admin) == []
    assert [i["status"] for i in incidents(client, admin)] == ["open"]


def test_disabling_the_defence_records_nothing(client, admin, monkeypatch):
    monkeypatch.setenv("AUTH_DEFENSE_ENABLED", "false")
    fail(client, "EMP-1003", "203.0.113.82", 6)
    assert incidents(client, admin) == [] and client.get("/api/soc/auth/attempts", headers=admin).json()["rows"] == []


def test_automatic_locks_are_capped_per_hour_and_wait_for_an_analyst(client, admin, monkeypatch):
    monkeypatch.setenv("MAX_AUTO_LOCKS_PER_HOUR", "1")
    fail(client, "EMP-1001", "203.0.113.90", 5)
    fail(client, "EMP-1002", "203.0.113.91", 5)
    assert status_of("EMP-1001") == "locked" and status_of("EMP-1002") == "active"
    pending = [a for a in actions(client, admin) if a["status"] == "pending_approval"]
    assert len(pending) == 1 and pending[0]["target"] == "EMP-1002" and "analyst must approve" in pending[0]["result"]
    overview = client.get("/api/soc/auth/overview", headers=admin).json()
    assert overview["pending_approval"] == 1
    approved = client.post(f"/api/soc/auth/incidents/{pending[0]['incident_id']}/actions", headers=admin,
                           json={"action": "lock_account", "reason": "approved after review", "confirm": True})
    assert approved.status_code == 201 and approved.json()["status"] == "completed" and status_of("EMP-1002") == "locked"


# ------------------------------------------------------------------------------------------------- SOC API and roles
def test_the_soc_endpoints_require_a_security_administrator(client, admin):
    employee = auth_header(client, "EMP-1003")
    paths = ["/api/soc/auth/overview", "/api/soc/auth/incidents", "/api/soc/auth/attempts", "/api/soc/auth/actions"]
    for path in paths:
        assert client.get(path).status_code == 401
        assert client.get(path, headers=employee).status_code == 403
        assert client.get(path, headers=admin).status_code == 200
    body = {"action": "lock_account", "target": "EMP-1001", "reason": "escalation attempt", "confirm": True}
    assert client.post("/api/soc/auth/actions", json=body).status_code == 401
    assert client.post("/api/soc/auth/actions", json=body, headers=employee).status_code == 403
    assert status_of("EMP-1001") == "active"


def test_manual_responses_are_validated_confirmed_idempotent_and_audited(client, admin):
    base = {"action": "lock_account", "target": "EMP-1003", "reason": "analyst test"}
    assert manual(client, admin, **base).status_code == 409                                    # disruptive: needs confirm
    for bad in ({**base, "action": "format_disk"}, {**base, "reason": "abc"}, {**base, "reason": "x" * 301},
                {**base, "minutes": 0}, {**base, "minutes": 10**9}, {"action": "block_ip", "target": "999.1.1.1", "reason": "bad address here", "confirm": True},
                {"action": "lock_account", "reason": "no target given", "confirm": True}):
        assert manual(client, admin, **bad).status_code == 422, bad
    assert manual(client, admin, action="lock_account", target="SEC-9011", reason="self lock attempt", confirm=True).status_code == 422
    assert manual(client, admin, action="lock_account", target="EMP-4040", reason="no such employee", confirm=True).status_code == 404

    headers = {**admin, "Idempotency-Key": "manual-lock-0001"}
    first = client.post("/api/soc/auth/actions", headers=headers, json={**base, "confirm": True, "minutes": 30})
    again = client.post("/api/soc/auth/actions", headers=headers, json={**base, "confirm": True, "minutes": 30})
    assert first.status_code == 201 and first.json()["status"] == "completed" and not first.json()["automatic"]
    assert again.json()["id"] == first.json()["id"] and again.json()["replayed"] is True
    assert len([a for a in actions(client, admin) if a["action"] == "lock_account"]) == 1
    assert status_of("EMP-1003") == "locked"
    assert manual(client, admin, action="unlock_account", target="EMP-1003", reason="verified owner").json()["status"] == "completed"
    assert manual(client, admin, action="unlock_account", target="EMP-1003", reason="verified owner").json()["status"] == "skipped"
    assert manual(client, admin, action="block_ip", target="10.0.0.9", reason="trying a private range", confirm=True).json()["status"] == "skipped"
    con = sqlite3.connect(engine.url.database)
    logged = {r[0] for r in con.execute("select action from audit_logs")}
    con.close()
    assert {"account_locked", "account_unlocked"} <= logged


def test_incident_status_changes_need_a_note_and_are_audited(client, admin):
    fail(client, "EMP-1001", "203.0.113.95", 5)
    (incident,) = incidents(client, admin)
    url = f"/api/soc/auth/incidents/{incident['id']}/status"
    assert client.post(url, headers=admin, json={"status": "resolved"}).status_code == 422
    assert client.post(url, headers=admin, json={"status": "nonsense", "note": "valid note"}).status_code == 422
    done = client.post(url, headers=admin, json={"status": "resolved", "note": "owner confirmed typing errors"})
    assert done.status_code == 200 and done.json()["status"] == "resolved" and done.json()["resolution_note"]
    assert incidents(client, admin, status="active") == []
    assert client.get("/api/soc/auth/incidents/999999", headers=admin).status_code == 404


def test_the_incident_and_attempt_feeds_filter(client, admin):
    fail(client, "EMP-1001", "203.0.113.96", 5)
    fail(client, "EMP-1002", "203.0.113.97", 2)
    assert [i["employee_id"] for i in incidents(client, admin, employee="EMP-1001")] == ["EMP-1001"]
    assert incidents(client, admin, employee="EMP-1002") == [] and incidents(client, admin, severity="critical") == []
    assert incidents(client, admin, kind="credential_stuffing") == []
    assert client.get("/api/soc/auth/incidents", headers=admin, params={"kind": "bogus"}).status_code == 422
    assert client.get("/api/soc/auth/incidents", headers=admin, params={"severity": "bogus"}).status_code == 422
    rows = client.get("/api/soc/auth/attempts", headers=admin, params={"ip": "203.0.113.97"}).json()["rows"]
    assert len(rows) == 2 and {r["account"] for r in rows} == {"EMP-1002"}
    assert client.get("/api/soc/auth/attempts", headers=admin, params={"outcome": "success"}).json()["rows"] == []


# -------------------------------------------------------------------------- concurrency, expiry, persistence, migration
def test_concurrent_failures_open_one_incident_and_lock_once(client, admin):
    barrier = threading.Barrier(12)

    def one(_):
        with SessionLocal() as db:
            employee = db.scalar(select(Employee).where(Employee.employee_code == "EMP-1002"))
            barrier.wait()                                                   # all twelve attempts land together
            auth_response.record_attempt(db, ip="203.0.113.110", identifier="EMP-1002", employee=employee, outcome="failure",
                                         reason="bad_password")

    with ThreadPoolExecutor(12) as pool:
        list(pool.map(one, range(12)))
    assert db_read(lambda db: db.query(AuthAttempt).count()) == 12
    brute = [i for i in incidents(client, admin) if i["kind"] == "account_brute_force"]
    assert len(brute) == 1 and status_of("EMP-1002") == "locked"
    assert len([a for a in actions(client, admin) if a["action"] == "lock_account" and a["status"] == "completed"]) == 1


def test_an_expired_block_stops_applying_and_is_closed_with_a_record(client, admin):
    attacker = "203.0.113.120"
    made = manual(client, admin, action="block_ip", target=attacker, reason="temporary test block", minutes=30, confirm=True)
    assert made.status_code == 201 and made.json()["status"] == "completed" and made.json()["expires_at"]["utc"]
    assert db_read(lambda db: controls.is_ip_blocked(db, attacker))
    con = sqlite3.connect(engine.url.database)
    con.execute("update ip_blocks set expires_at = ? where ip = ?", ((utcnow() - timedelta(minutes=1)).isoformat(sep=" "), attacker))
    con.commit()
    con.close()
    assert not db_read(lambda db: controls.is_ip_blocked(db, attacker))                       # enforcement stops at expiry at once
    assert signin(client, "EMP-1001", None, attacker).status_code == 200
    client.get("/api/soc/auth/overview", headers=admin)                                        # reading the overview closes it
    closed = [a for a in actions(client, admin) if a["action"] == "unblock_ip" and a["policy"] == "block_expiry"]
    assert len(closed) == 1 and closed[0]["target"] == attacker


def test_incidents_blocks_and_locks_survive_a_database_restart(client, admin):
    fail(client, "EMP-1001", "203.0.113.130", 5)
    manual(client, admin, action="block_ip", target="203.0.113.131", reason="persistence check", minutes=60, confirm=True)
    engine.dispose()                                                                            # drop every pooled connection
    assert status_of("EMP-1001") == "locked"
    assert db_read(lambda db: controls.is_ip_blocked(db, "203.0.113.131"))
    assert db_read(lambda db: db.query(AuthAttempt).count()) == 5
    assert len(incidents(client, admin)) == 1


def test_migration_4_upgrades_a_version_3_database_in_place(tmp_path):
    db = create_engine(f"sqlite:///{(tmp_path / 'v3.db').as_posix()}")
    migrations.upgrade(db)
    with db.begin() as conn:
        for table in ("auth_response_actions", "auth_incidents", "auth_attempts", "access_denials", "export_requests", "ip_blocks"):
            conn.exec_driver_sql(f"DROP TABLE {table}")
        for column in ("lock_reason", "locked_at", "lock_expires_at", "locked_by"):
            conn.exec_driver_sql(f"ALTER TABLE employees DROP COLUMN {column}")
        conn.exec_driver_sql("DELETE FROM schema_migrations WHERE version = 4")
    assert migrations.current_version(db) == 3
    assert migrations.upgrade(db) == [4]
    names = set(inspect(db).get_table_names())
    assert {"auth_attempts", "auth_incidents", "auth_response_actions", "ip_blocks", "access_denials", "export_requests"} <= names
    assert {"lock_reason", "locked_at", "lock_expires_at", "locked_by"} <= {c["name"] for c in inspect(db).get_columns("employees")}
    assert migrations.upgrade(db) == []


# -------------------------------------------------------------------------------------------------- client address
def test_the_client_address_is_trusted_only_from_our_own_dashboards(client, admin):
    spoof = client.post("/api/auth/login", json={"employee_id": "EMP-1001", "password": WRONG},
                        headers={"X-Client-IP": "203.0.113.140", "X-Forwarded-For": "203.0.113.141"})
    assert spoof.status_code == 401
    wrong_key = client.post("/api/auth/login", json={"employee_id": "EMP-1001", "password": WRONG},
                            headers={"X-Frontend-Key": "not-the-key", "X-Client-IP": "203.0.113.142"})
    assert wrong_key.status_code == 401
    garbage = signin(client, "EMP-1001", WRONG, "not-an-ip")
    assert garbage.status_code == 401
    recorded = {r["source_ip"] for r in client.get("/api/soc/auth/attempts", headers=admin).json()["rows"]}
    assert not recorded & {"203.0.113.140", "203.0.113.141", "203.0.113.142", "not-an-ip"}       # none of them was believed
    assert all(ipaddress.ip_address(ip) for ip in recorded)


def test_sessions_are_revoked_when_an_address_is_blocked(client, admin):
    token = bearer(signin(client, "EMP-1003", None, "203.0.113.150"))
    assert client.get("/api/employees/me", headers={**token, "X-Frontend-Key": KEY, "X-Client-IP": "203.0.113.150"}).status_code == 200
    made = manual(client, admin, action="block_ip", target="203.0.113.150", reason="block this address", confirm=True)
    assert made.status_code == 201 and made.json()["details"]["sessions_revoked"] == 1
    assert client.get("/api/employees/me", headers=token).status_code == 401
    assert db_read(lambda db: db.query(EmployeeSession).filter(EmployeeSession.ip_address == "203.0.113.150",
                                                              EmployeeSession.revoked_at.is_(None)).count()) == 0
    assert db_read(lambda db: db.query(ResponseAction).filter(ResponseAction.target == "203.0.113.150").count()) == 1
    assert db_read(lambda db: db.query(AuthIncident).count()) == 0                    # a manual block needs no incident


@pytest.mark.parametrize("value", ["10.1.2.3", "127.0.0.1", "192.168.0.9", "169.254.1.1", "::1", "fd00::1", "0.0.0.0"])
def test_unblockable_addresses_by_rule(value):
    from backend.auth_policy import get_policy, unblockable_reason

    assert unblockable_reason(value, get_policy())


def test_documentation_ranges_and_public_addresses_are_blockable():
    from backend.auth_policy import get_policy, unblockable_reason

    for value in ("203.0.113.5", "198.51.100.9", "192.0.2.1", "8.8.8.8", "2001:db8::1"):
        assert unblockable_reason(value, get_policy()) is None
    assert unblockable_reason("203.0.113.5", get_policy(), {"203.0.113.5"}) == "registered as an employee's known address"
