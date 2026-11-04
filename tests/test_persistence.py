"""Persistence and multi-client behaviour: schema migrations, constraints, indexes, event de-duplication, concurrent
ingestion, transactional rollback, bounded dashboard queries, several dashboard clients on one store, and the database
copy tool. The tests that need a separate backend process (hard kill, Streamlit reruns) are at the end of the file."""
import ast
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from conftest import app_now, auth_header
from sqlalchemy import event as sa_event
from sqlalchemy import func, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from test_runtime import ADMIN_PASSWORD, EMPLOYEE_PASSWORD, Backend, _run_app, _sign_in

from backend import event_service, migrations, soc_service, threat_engine
from backend.config import get_settings, normalize_database_url, redact_url
from backend.database import Base, SessionLocal, engine, utcnow
from backend.db_tools import CopyError, copy_database, count_rows, make_engine
from backend.event_service import record_event
from backend.models import (
    AttackInvestigation,
    AuditLog,
    Employee,
    ResponseControl,
    SecurityAlert,
    SecurityEvent,
    SimulationRun,
)
from frontend.api_client import env_seconds

ROOT = Path(__file__).resolve().parent.parent
PORTAL_IP = "10.20.1.11"


def sqlite_engine(tmp_path, name="db.db"):
    return make_engine(f"sqlite:///{(tmp_path / name).as_posix()}")


def make_employee(db: Session, name: str, **extra) -> Employee:
    employee = Employee(username=name, full_name=name.title(), email=f"{name}@westbridgebank.test", department="Operations",
                        job_role="Analyst", password_hash="not-a-real-hash", known_ips=[PORTAL_IP], **extra)
    db.add(employee)
    db.flush()
    return employee


def person(username: str) -> Employee:
    with SessionLocal() as db:
        return db.scalar(select(Employee).where(Employee.username == username))


def employee_in(db: Session, username: str) -> Employee:
    """The employee as loaded by this session (an object cannot be shared between threads' sessions)."""
    return db.scalar(select(Employee).where(Employee.username == username))


def count_events(**filters) -> int:
    with SessionLocal() as db:
        return len(db.scalars(select(SecurityEvent.id).filter_by(**filters)).all())


# =============================================================================== frontends hold no database access
def test_frontends_never_open_the_database_or_import_the_data_layer():
    """The dashboards only call the backend API; there is no UI-side store that could drift from the shared one."""
    forbidden = {"sqlalchemy", "sqlite3", "psycopg", "psycopg2"}
    forbidden_backend = {"backend.database", "backend.models", "backend.migrations", "backend.db_tools"}
    for path in sorted((ROOT / "frontend").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            for name in names:
                assert name.split(".")[0] not in forbidden and name not in forbidden_backend, (path.name, name)


# =============================================================================== migrations
def test_a_new_database_is_created_at_the_current_version_with_every_index(tmp_path):
    db = sqlite_engine(tmp_path)
    assert migrations.upgrade(db) == [1, 2]
    assert migrations.current_version(db) == migrations.CURRENT_VERSION
    for table in Base.metadata.sorted_tables:
        present = {i["name"] for i in inspect(db).get_indexes(table.name)}
        assert {i.name for i in table.indexes} <= present, table.name
    assert migrations.upgrade(db) == []                                       # running it again changes nothing
    db.dispose()


def _legacy_database(tmp_path) -> "object":
    """A database as an earlier release left it: no version table and none of the uniqueness rules."""
    db = sqlite_engine(tmp_path, "legacy.db")
    migrations.upgrade(db)
    with db.begin() as conn:
        for name in ("uq_events_employee_request", "uq_alerts_one_open_per_employee", "uq_inv_one_active_per_employee",
                     "uq_controls_one_active"):
            conn.exec_driver_sql(f"DROP INDEX {name}")
        conn.exec_driver_sql("DROP TABLE schema_migrations")
    return db


def test_upgrading_an_old_database_keeps_every_row_and_repairs_duplicates_visibly(tmp_path):
    db = _legacy_database(tmp_path)
    with Session(db) as s:
        a, b = make_employee(s, "legacy.a"), make_employee(s, "legacy.b")
        a_id, b_id = a.id, b.id
        for _ in range(3):                                                    # the same client retry stored three times
            s.add(SecurityEvent(employee_id=a_id, event_type="login", source_ip=PORTAL_IP, request_id="retry-key-0001"))
        s.add(SecurityEvent(employee_id=b_id, event_type="login", source_ip=PORTAL_IP, request_id="retry-key-0001"))
        s.add(SecurityEvent(employee_id=a_id, event_type="login", source_ip=PORTAL_IP))
        for status in ("open", "investigating"):                              # two live alerts and two live cases for one person
            s.add(SecurityAlert(employee_id=a_id, severity="critical", status=status, title="t", description="d"))
        s.add_all([AttackInvestigation(employee_id=a_id, status="open"), AttackInvestigation(employee_id=a_id, status="contained")])
        s.add_all([ResponseControl(kind="blocked_ip", value="203.0.113.7", active=True, created_by=a_id) for _ in range(2)])
        s.commit()
    before = count_rows(db)

    assert migrations.upgrade(db) == [1, 2]
    after = count_rows(db)
    assert {k: v for k, v in after.items() if k != "audit_logs"} == {k: v for k, v in before.items() if k != "audit_logs"}
    with Session(db) as s:
        keyed = s.scalars(select(SecurityEvent).where(SecurityEvent.request_id == "retry-key-0001")).all()
        assert sorted(e.employee_id for e in keyed) == sorted([a_id, b_id])   # one per employee; the same key is allowed per person
        assert len(s.scalars(select(SecurityAlert).where(SecurityAlert.status.in_(["open", "investigating"]))).all()) == 1
        assert len(s.scalars(select(AttackInvestigation).where(AttackInvestigation.status.in_(["open", "contained"]))).all()) == 1
        assert len(s.scalars(select(ResponseControl).where(ResponseControl.active.is_(True))).all()) == 1
        repair = s.scalar(select(AuditLog).where(AuditLog.action == "schema_migration_repair"))
        assert repair is not None and repair.details["duplicate_request_ids_cleared"] == 2
    db.dispose()


def test_a_database_from_a_newer_release_is_refused_untouched(tmp_path):
    db = sqlite_engine(tmp_path)
    migrations.upgrade(db)
    with db.begin() as conn:
        conn.execute(migrations.schema_migrations.insert().values(version=99, name="future", applied_at=utcnow().replace(tzinfo=None)))
    with pytest.raises(migrations.MigrationError, match="newer than this application"):
        migrations.upgrade(db)
    db.dispose()


@pytest.mark.parametrize("sql, table", [
    ("SELECT * FROM security_events WHERE employee_id = 3 AND timestamp >= '2026-01-01'", "security_events"),
    ("SELECT count(*) FROM security_events WHERE timestamp >= '2026-01-01'", "security_events"),
    ("SELECT * FROM security_events WHERE source_ip = '203.0.113.9' AND timestamp >= '2026-01-01'", "security_events"),
    ("SELECT * FROM security_events WHERE session_id = 4", "security_events"),
    ("SELECT * FROM security_events WHERE simulation_run_id = 4", "security_events"),
    ("SELECT * FROM security_alerts WHERE status = 'open' AND severity = 'critical'", "security_alerts"),
    ("SELECT * FROM security_alerts WHERE employee_id = 3 AND status = 'resolved'", "security_alerts"),
    ("SELECT max(updated_at) FROM security_alerts", "security_alerts"),
    ("SELECT * FROM attack_investigations WHERE employee_id = 3 AND status = 'resolved'", "attack_investigations"),
    ("SELECT max(updated_at) FROM attack_investigations", "attack_investigations"),
    ("SELECT * FROM simulation_runs WHERE status = 'running'", "simulation_runs"),
    ("SELECT * FROM simulation_runs WHERE idempotency_key = 'k'", "simulation_runs"),
    ("SELECT * FROM risk_assessments WHERE employee_id = 3 AND created_at >= '2026-01-01'", "risk_assessments"),
    ("SELECT * FROM audit_logs WHERE timestamp >= '2026-01-01'", "audit_logs"),
])
def test_frequent_queries_are_answered_from_an_index(tmp_path, sql, table):
    db = sqlite_engine(tmp_path)
    migrations.upgrade(db)
    with db.connect() as conn:
        plan = " | ".join(row[-1] for row in conn.exec_driver_sql("EXPLAIN QUERY PLAN " + sql))
    assert f"SEARCH {table}" in plan and "SCAN" not in plan, plan
    db.dispose()


# =============================================================================== constraints
def test_the_database_itself_rejects_invalid_values_and_duplicates(tmp_path):
    db = sqlite_engine(tmp_path)
    migrations.upgrade(db)
    with Session(db) as s:
        emp = make_employee(s, "constraint.a")
        s.commit()
        emp_id = emp.id

    def rejected(obj):
        with Session(db) as s, pytest.raises(IntegrityError):
            s.add(obj)
            s.commit()

    alert = dict(employee_id=emp_id, title="t", description="d")
    rejected(SecurityAlert(**alert, severity="catastrophic", status="open"))
    rejected(SecurityAlert(**alert, severity="critical", status="weird"))
    rejected(SecurityEvent(employee_id=emp_id, event_type="login", source_ip=PORTAL_IP, outcome="maybe"))
    rejected(SecurityEvent(employee_id=emp_id, event_type="login", source_ip=PORTAL_IP, records_accessed=-1))
    rejected(AttackInvestigation(employee_id=emp_id, status="nope"))
    rejected(SimulationRun(scenario="x", seed=1, seed_mode="fixed", status="paused"))
    rejected(Employee(username="x", full_name="x", email="x@westbridgebank.test", department="d", job_role="j",
                      password_hash="h", status="vanished"))

    with Session(db) as s:                                                    # the de-duplication key, per employee
        s.add(SecurityEvent(employee_id=emp_id, event_type="login", source_ip=PORTAL_IP, request_id="same-key-00001"))
        s.add_all([SecurityEvent(employee_id=emp_id, event_type="login", source_ip=PORTAL_IP) for _ in range(3)])  # NULL keys never clash
        s.commit()
    rejected(SecurityEvent(employee_id=emp_id, event_type="logout", source_ip=PORTAL_IP, request_id="same-key-00001"))

    with Session(db) as s:                                                    # one live alert / case / run / block at a time
        s.add(SecurityAlert(**alert, severity="critical", status="open"))
        s.add(AttackInvestigation(employee_id=emp_id, status="open"))
        s.add(SimulationRun(scenario="x", seed=1, seed_mode="fixed", status="running", active_slot=1))
        s.add(ResponseControl(kind="blocked_ip", value="203.0.113.5", active=True, created_by=emp_id))
        s.commit()
    rejected(SecurityAlert(**alert, severity="high_risk", status="investigating"))
    rejected(AttackInvestigation(employee_id=emp_id, status="contained"))
    rejected(SimulationRun(scenario="y", seed=2, seed_mode="fixed", status="queued", active_slot=1))
    rejected(ResponseControl(kind="blocked_ip", value="203.0.113.5", active=True, created_by=emp_id))
    with Session(db) as s:                                                    # a closed one does not block a new one
        s.add(SecurityAlert(**alert, severity="critical", status="resolved"))
        s.add(ResponseControl(kind="blocked_ip", value="203.0.113.5", active=False, created_by=emp_id))
        s.commit()
    db.dispose()


# =============================================================================== event de-duplication and concurrency
def test_a_repeated_request_id_stores_and_scores_the_event_once(client):
    alice, key = person("alice.morgan"), f"dedup-{uuid.uuid4().hex[:12]}#0"
    with SessionLocal() as db:
        first = record_event(db, alice, "resource_access", source_ip=PORTAL_IP, resource="my-profile", request_id=key)
    with SessionLocal() as db:
        again = record_event(db, alice, "resource_access", source_ip=PORTAL_IP, resource="my-profile", request_id=key)
    assert not first.duplicate and again.duplicate and again.event.id == first.event.id
    assert count_events(request_id=key) == 1
    other = person("bob.chen")                                                # the key is scoped to the employee
    with SessionLocal() as db:
        assert not record_event(db, other, "resource_access", source_ip=PORTAL_IP, resource="my-profile", request_id=key).duplicate


def test_concurrent_requests_with_one_key_store_exactly_one_event(client):
    key, barrier = f"race-{uuid.uuid4().hex[:12]}#0", threading.Barrier(12)

    def submit(_):
        barrier.wait()
        with SessionLocal() as db:
            return record_event(db, employee_in(db, "alice.morgan"), "resource_access", source_ip=PORTAL_IP,
                                resource="my-profile", request_id=key)

    with ThreadPoolExecutor(12) as pool:
        results = list(pool.map(submit, range(12)))
    assert sum(not r.duplicate for r in results) == 1 and len({r.event.id for r in results}) == 1
    assert count_events(request_id=key) == 1


def test_concurrent_ingestion_of_different_events_loses_nothing_and_never_hits_a_lock_error(client):
    names = ("alice.morgan", "bob.chen", "carol.diaz")
    marker, errors = uuid.uuid4().hex[:8], []

    def worker(i):
        try:
            for n in range(5):
                with SessionLocal() as db:
                    record_event(db, employee_in(db, names[i % 3]), "resource_access", source_ip=PORTAL_IP,
                                 resource="my-profile", request_id=f"{marker}-{i}-{n}-0000")
        except Exception as exc:  # noqa: BLE001 - the test reports whatever escaped
            errors.append(repr(exc))

    with ThreadPoolExecutor(9) as pool:
        list(pool.map(worker, range(9)))
    assert not errors, errors
    with SessionLocal() as db:
        stored = db.scalars(select(SecurityEvent.request_id).where(SecurityEvent.request_id.like(f"{marker}-%"))).all()
    assert len(stored) == len(set(stored)) == 45


def test_simultaneous_attack_events_leave_one_live_alert_and_one_live_investigation(client, admin):
    david_id, errors = person("david.kumar").id, []
    attacker, tag = "185.220.101.45", uuid.uuid4().hex[:8]

    def attack(i):
        try:
            with SessionLocal() as db:
                david = db.get(Employee, david_id)
                record_event(db, david, "login", source_ip=attacker, request_id=f"{tag}-{i}-login-0")
                record_event(db, david, "resource_access", source_ip=attacker, resource="hr-records", outcome="denied",
                             request_id=f"{tag}-{i}-hr-0000")
                record_event(db, david, "file_download", source_ip=attacker, resource="source-code-repo",
                             records_accessed=25_000, records_downloaded=25_000, request_id=f"{tag}-{i}-dl-0000")
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    with ThreadPoolExecutor(6) as pool:
        list(pool.map(attack, range(6)))
    assert not errors, errors
    with SessionLocal() as db:
        live_alerts = db.scalars(select(SecurityAlert).where(SecurityAlert.employee_id == david_id,
                                                             SecurityAlert.status.in_(["open", "investigating"]))).all()
        live_cases = db.scalars(select(AttackInvestigation).where(AttackInvestigation.employee_id == david_id,
                                                                  AttackInvestigation.status.in_(["open", "contained"]))).all()
    assert len(live_alerts) <= 1 and len(live_cases) <= 1


# =============================================================================== transactions
@pytest.mark.parametrize("stage", ["scoring", "alerting"])
def test_a_failure_while_scoring_or_alerting_stores_nothing(client, monkeypatch, stage):
    david, key = person("david.kumar"), f"txn-{uuid.uuid4().hex[:12]}#0"

    def boom(*_a, **_k):
        raise RuntimeError("injected failure")

    if stage == "scoring":
        monkeypatch.setattr(threat_engine, "assess_and_store", boom)
    else:
        monkeypatch.setattr(event_service, "_maybe_raise_alert", boom)
    with SessionLocal() as db:
        last_event = db.scalar(select(func.max(SecurityEvent.id)))
    with pytest.raises(RuntimeError, match="injected failure"):
        with SessionLocal() as db:
            record_event(db, david, "file_download", source_ip="185.220.101.45", resource="source-code-repo",
                         records_accessed=25_000, records_downloaded=25_000, request_id=key)
    assert count_events(request_id=key) == 0                                  # the event row was rolled back with the rest
    with SessionLocal() as db:
        assert db.scalar(select(func.max(SecurityEvent.id))) == last_event
    monkeypatch.undo()
    with SessionLocal() as db:                                                # and the same key can then be used normally
        assert not record_event(db, david, "resource_access", source_ip=PORTAL_IP, resource="my-profile", request_id=key).duplicate


# =============================================================================== bounded dashboard queries
def test_the_change_token_never_scans_the_event_tables(client, admin):
    statements: list[str] = []

    def capture(_conn, _cursor, statement, *_rest):
        statements.append(statement.lower())

    sa_event.listen(engine, "before_cursor_execute", capture)
    try:
        assert client.get("/api/soc/version", headers=admin).status_code == 200
    finally:
        sa_event.remove(engine, "before_cursor_execute", capture)
    selects = [s for s in statements if s.lstrip().startswith("select")]
    assert 0 < len(selects) <= 20                                             # a fixed handful of indexed reads (plus authentication)
    heavy = [s for s in selects if "count(" in s and any(t in s for t in ("security_events", "security_alerts", "attack_investigations"))]
    assert not heavy, heavy


def test_only_recently_active_employees_are_assessed(client, monkeypatch):
    calls: list[int] = []
    real = threat_engine.assess
    monkeypatch.setattr(threat_engine, "assess", lambda db, emp, as_of=None: calls.append(emp.id) or real(db, emp, as_of))
    with SessionLocal() as db:
        quiet = threat_engine.assess_all(db, as_of=utcnow() + timedelta(days=400))      # nothing happened in this window
        assert not calls and all(t.level == "normal" and t.score == 0 for t in quiet.values())
        alice = person("alice.morgan")
        record_event(db, alice, "resource_access", source_ip=PORTAL_IP, resource="my-profile", request_id=f"act-{uuid.uuid4().hex[:12]}#0")
        calls.clear()
        everyone = threat_engine.assess_all(db)
        assert alice.id in calls and len(calls) < len(everyone)


def test_dashboard_totals_cover_a_bounded_window_and_say_so(client, admin):
    overview = client.get("/api/soc/overview", headers=admin).json()
    window = get_settings().dashboard_window_days
    assert overview["window_days"] == window
    since = utcnow() - timedelta(days=window)
    with SessionLocal() as db:
        expected = len(db.scalars(select(SecurityEvent.id).where(SecurityEvent.timestamp >= since)).all())
    assert overview["kpis"]["total_events"] == expected and overview["kpis"]["events_24h"] <= overview["kpis"]["total_events"]
    assert soc_service.window_start(app_now()) < app_now()


def test_the_event_feed_pages_with_a_keyset_cursor_and_caps_page_size(client, admin):
    first = client.get("/api/soc/events", headers=admin, params={"limit": 5}).json()
    assert first["has_more"] and len(first["rows"]) == 5 and first["next_before_id"] == first["rows"][-1]["id"]
    second = client.get("/api/soc/events", headers=admin, params={"limit": 5, "before_id": first["next_before_id"]}).json()
    ids = [r["id"] for r in first["rows"]] + [r["id"] for r in second["rows"]]
    assert ids == sorted(set(ids), reverse=True) and len(ids) == 10          # no overlap, no gap, newest first
    too_big = get_settings().max_page_size + 1
    for path in ("/api/soc/events", "/api/events", "/api/alerts", "/api/investigations"):
        assert client.get(path, headers=admin, params={"limit": too_big}).status_code == 422
    assert client.get("/api/soc/investigations", headers=admin, params={"limit": too_big}).status_code == 422


# =============================================================================== several clients, one store
def test_two_soc_sessions_and_a_portal_session_see_the_same_data(client, admin):
    second_admin = auth_header(client, "SEC-9011")
    employee = auth_header(client, "EMP-1001")
    assert second_admin != admin                                              # genuinely separate sessions
    before = [client.get("/api/soc/version", headers=h).json()["token"] for h in (admin, second_admin)]
    assert before[0] == before[1]

    last = client.get("/api/soc/events", headers=admin, params={"limit": 1}).json()["latest_id"]
    assert client.get("/api/portal/profile", headers=employee).status_code == 200
    after = [client.get("/api/soc/version", headers=h).json()["token"] for h in (admin, second_admin)]
    assert after[0] == after[1] != before[0]                                  # one change, seen identically by both
    feeds = [client.get("/api/soc/events", headers=h, params={"employee": "EMP-1001", "limit": 20}).json() for h in (admin, second_admin)]
    assert feeds[0] == feeds[1] and feeds[0]["latest_id"] > last
    kpis = [client.get("/api/soc/overview", headers=h).json()["kpis"] for h in (admin, second_admin)]
    assert kpis[0] == kpis[1]
    mine = client.get("/api/events/me", headers=employee, params={"limit": 5}).json()   # the employee's own view is the same rows
    assert {e["id"] for e in mine} <= {r["id"] for r in client.get(
        "/api/soc/events", headers=admin, params={"employee": "EMP-1001", "limit": 50}).json()["rows"]}


def test_the_same_idempotency_key_over_http_records_one_event_and_bad_keys_are_ignored(client, admin):
    token = auth_header(client, "EMP-1001")
    last = client.get("/api/soc/events", headers=admin, params={"limit": 1}).json()["latest_id"]

    def profile_events():
        rows = client.get("/api/soc/events", headers=admin, params={"employee": "EMP-1001", "limit": 50}).json()["rows"]
        return [r for r in rows if r["id"] > last and r["resource"] == "my-profile"]

    key = uuid.uuid4().hex
    for _ in range(3):
        assert client.get("/api/portal/profile", headers={**token, "Idempotency-Key": key}).status_code == 200
    assert len(profile_events()) == 1
    assert client.get("/api/portal/profile", headers={**token, "Idempotency-Key": uuid.uuid4().hex}).status_code == 200
    assert len(profile_events()) == 2
    for _ in range(2):                                                        # too short / illegal characters: ignored, not rejected
        assert client.get("/api/portal/profile", headers={**token, "Idempotency-Key": "x"}).status_code == 200
        assert client.get("/api/portal/profile", headers={**token, "Idempotency-Key": "bad key with spaces!"}).status_code == 200
    assert len(profile_events()) == 6


def test_the_database_status_endpoint_is_admin_only_and_leaks_no_paths_or_secrets(client, admin, db_path):
    body = client.get("/api/system/database", headers=admin).json()
    assert body["dialect"] == "sqlite" and body["schema_version"] == body["latest_schema_version"] == migrations.CURRENT_VERSION
    assert body["persistent_shared_store"] is False and body["journal_mode"] == "wal" and body["row_counts"]["employees"] >= 10
    assert str(db_path.parent) not in str(body) and "password" not in str(body).lower()
    assert client.get("/api/system/database", headers=auth_header(client, "EMP-1001")).status_code == 403
    assert client.get("/api/system/database").status_code == 401


def test_health_reports_database_trouble_as_503_without_details(client, monkeypatch):
    import backend.main as main

    assert client.get("/api/health").json()["status"] == "ok"

    def down():
        raise RuntimeError("could not connect to server at host db-internal.example port 5432")

    monkeypatch.setattr(main, "check_database", down)
    response = client.get("/api/health")
    assert response.status_code == 503 and response.headers["Retry-After"] and "db-internal" not in response.text


# =============================================================================== configuration helpers
def test_database_urls_are_normalised_and_passwords_are_redacted():
    assert normalize_database_url("postgres://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert normalize_database_url("postgresql://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert normalize_database_url("postgresql+psycopg://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert normalize_database_url("sqlite:///./x.db") == "sqlite:///./x.db"
    assert "hunter2" not in redact_url("postgresql+psycopg://user:hunter2@db.example/w") and "db.example" in redact_url("postgresql://user:hunter2@db.example/w")


def test_refresh_intervals_come_from_the_environment_and_cannot_be_set_dangerously_low(monkeypatch):
    monkeypatch.delenv("SOC_TEST_INTERVAL", raising=False)
    assert env_seconds("SOC_TEST_INTERVAL", 3, 1) == 3
    monkeypatch.setenv("SOC_TEST_INTERVAL", "10")
    assert env_seconds("SOC_TEST_INTERVAL", 3, 1) == 10
    monkeypatch.setenv("SOC_TEST_INTERVAL", "0.01")
    assert env_seconds("SOC_TEST_INTERVAL", 3, 1) == 1                       # raised to the minimum
    monkeypatch.setenv("SOC_TEST_INTERVAL", "soon")
    assert env_seconds("SOC_TEST_INTERVAL", 3, 1) == 3                       # unusable value: the default
    for name, floor in (("SOC_REFRESH_SECONDS", 1), ("SOC_CACHE_SECONDS", 5)):
        text = (ROOT / "frontend" / "soc_dashboard.py").read_text(encoding="utf-8")
        assert f'env_seconds("{name}"' in text and f", {floor})" in text


def test_database_settings_are_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("DASHBOARD_WINDOW_DAYS", "7")
    monkeypatch.setenv("MAX_PAGE_SIZE", "50")
    monkeypatch.setenv("DB_POOL_SIZE", "3")
    get_settings.cache_clear()
    try:
        s = get_settings()
        assert (s.dashboard_window_days, s.max_page_size, s.db_pool_size) == (7, 50, 3)
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


# =============================================================================== the copy tool (SQLite to SQLite here)
def _seeded_source(tmp_path):
    """A real seeded database at the current version, made by the application's own start-up path."""
    backend = Backend(tmp_path / "src")
    backend.directory.mkdir()
    backend.start()
    admin = backend.login("SEC-9011", ADMIN_PASSWORD)
    backend.get("/api/employees", admin)
    backend.stop()
    return f"sqlite:///{(backend.directory / 'runtime.db').as_posix()}"


def test_the_copy_tool_moves_every_row_and_never_overwrites_or_half_fills(tmp_path):
    source = _seeded_source(tmp_path)
    target = f"sqlite:///{(tmp_path / 'target.db').as_posix()}"
    expected = count_rows(make_engine(source))
    assert expected["employees"] >= 10 and expected["security_events"] > 100

    report = copy_database(source, target, batch=50)
    assert report.rows == expected and report.target_version == migrations.CURRENT_VERSION
    copied = make_engine(target)
    with Session(copied) as s:                                                # the self-reference (created_by_id) survived
        assert s.scalar(select(Employee.id).limit(1)) is not None
    with Session(make_engine(source)) as a, Session(copied) as b:
        assert [e.username for e in a.scalars(select(Employee).order_by(Employee.id))] == [e.username for e in b.scalars(select(Employee).order_by(Employee.id))]
        assert [(e.id, e.request_id, e.timestamp) for e in a.scalars(select(SecurityEvent).order_by(SecurityEvent.id))] == \
               [(e.id, e.request_id, e.timestamp) for e in b.scalars(select(SecurityEvent).order_by(SecurityEvent.id))]
    with pytest.raises(CopyError, match="already holds rows"):
        copy_database(source, target)                                         # a second copy would duplicate: refused
    assert count_rows(copied) == expected
    with pytest.raises(CopyError, match="same database"):
        copy_database(source, source)


def test_the_copy_tool_refuses_a_source_that_is_not_at_the_current_version(tmp_path):
    old = _legacy_database(tmp_path)
    url = str(old.url)
    old.dispose()
    with pytest.raises(CopyError, match="schema version 0"):
        copy_database(url, f"sqlite:///{(tmp_path / 'never.db').as_posix()}")
    assert not (tmp_path / "never.db").exists()                               # nothing was created for the failed copy


# =============================================================================== a real backend process
@pytest.fixture(scope="module")
def live(tmp_path_factory):
    backend = Backend(tmp_path_factory.mktemp("persist"))
    backend.env["DB_BUSY_TIMEOUT_SECONDS"] = "2"                              # keeps the lock-contention test short
    backend.start()
    yield backend
    backend.stop()


def _live_events(live, admin, mark, **filters):
    rows = live.get("/api/soc/events", admin, limit=200, **filters)["rows"]
    return [r for r in rows if r["id"] > mark]


def test_streamlit_reruns_and_double_clicks_record_activity_once(live, monkeypatch):
    admin = live.login("SEC-9011", ADMIN_PASSWORD)
    monkeypatch.setenv("PORTAL_REPEAT_WINDOW_SECONDS", "60")
    at = _sign_in(_run_app("frontend/employee_portal.py", live, monkeypatch), "EMP-1001", EMPLOYEE_PASSWORD)
    at = at.button(key="nav_Documents").click().run()
    assert not at.exception
    mark = live.get("/api/soc/events", admin, limit=1)["latest_id"]

    for _ in range(3):                                                        # reruns with no user action
        at = at.run()
    assert not _live_events(live, admin, mark, employee="EMP-1001")

    def request_download(at):
        return next(b for b in at.button if b.label == "Request download").click().run()

    at = request_download(at)
    at = request_download(at)                                                 # a double click
    downloads = [r for r in _live_events(live, admin, mark, employee="EMP-1001") if r["event_type"] == "file_download"]
    assert len(downloads) == 1

    monkeypatch.setenv("PORTAL_REPEAT_WINDOW_SECONDS", "0")                   # a deliberate repeat is a new action
    request_download(at)
    downloads = [r for r in _live_events(live, admin, mark, employee="EMP-1001") if r["event_type"] == "file_download"]
    assert len(downloads) == 2


def test_a_hard_kill_loses_nothing_that_was_stored_and_fails_the_interrupted_run(live):
    admin = live.login("SEC-9011", ADMIN_PASSWORD)
    import requests

    david = next(e["id"] for e in live.get("/api/employees", admin) if e["username"] == "david.kumar")
    live_run = requests.post(f"{live.url}/api/simulation/runs", headers=admin, timeout=15,
                             json={"scenario": "compromised_account_campaign", "pace": "demo", "seed": 11, "target_employee_id": david})
    assert live_run.status_code == 202, live_run.text
    run_id = live_run.json()["id"]
    deadline = time.time() + 60
    while time.time() < deadline and live.get(f"/api/simulation/runs/{run_id}", admin)["status"] != "running":
        time.sleep(0.2)
    deadline = time.time() + 60
    while time.time() < deadline and live.get(f"/api/simulation/runs/{run_id}", admin)["steps_done"] < 1:
        time.sleep(0.2)
    assert live.get(f"/api/simulation/runs/{run_id}", admin)["status"] == "running"
    stored = live.get("/api/events", admin, limit=500)["total"]
    overview_events = live.get("/api/soc/overview", admin)["kpis"]["total_events"]
    sim_events = live.get("/api/events", admin, synthetic="true", limit=500)["total"]

    live.process.kill()                                                       # no graceful shutdown at all
    live.process.wait(timeout=15)
    live.start()

    admin = live.login("SEC-9011", ADMIN_PASSWORD)
    run = live.get(f"/api/simulation/runs/{run_id}", admin)
    assert run["status"] == "failed" and run["steps_done"] >= 1               # recorded as interrupted, not left "running"
    assert live.get("/api/simulation/status", admin).get("active_run_id") is None
    assert live.get("/api/events", admin, limit=500)["total"] >= stored
    assert live.get("/api/events", admin, synthetic="true", limit=500)["total"] >= sim_events
    assert live.get("/api/soc/overview", admin)["kpis"]["total_events"] >= overview_events
    assert live.get("/api/system/database", admin)["schema_version"] == migrations.CURRENT_VERSION
    started = requests.post(f"{live.url}/api/simulation/runs", headers=admin, timeout=15, json={"scenario": "benign_activity", "pace": "instant", "seed": 3})
    assert started.status_code == 202                                         # the single run slot was freed


def test_containment_and_blocked_addresses_survive_a_restart(live):
    import requests

    admin = live.login("SEC-9011", ADMIN_PASSWORD)
    bob = next(e["id"] for e in live.get("/api/employees", admin) if e["username"] == "bob.chen")
    body = {"employee_id": bob, "action_type": "lock_account", "reason": "Simulated drill", "confirm": True,
            "idempotency_key": "restart-test-0001"}
    response = requests.post(f"{live.url}/api/containment", headers=admin, timeout=15, json=body)
    assert response.status_code in (200, 201), response.text
    action_id = response.json()["id"]

    live.stop()
    live.start()
    admin = live.login("SEC-9011", ADMIN_PASSWORD)
    assert next(e for e in live.get("/api/employees", admin) if e["id"] == bob)["status"] == "locked"
    assert action_id in {a["id"] for a in live.get("/api/containment", admin, employee_id=bob)}
    retry = requests.post(f"{live.url}/api/containment", headers=admin, timeout=15, json=body)
    assert retry.status_code == 200 and retry.json()["id"] == action_id       # the retry after a restart replays, not repeats


def test_a_busy_database_gives_a_503_with_retry_after_and_recovers(live):
    """Another connection holds the SQLite write lock past the busy timeout: the API says "retry", leaks nothing, then recovers."""
    import requests

    from data.demo_accounts import demo_password

    employee = live.login("EMP-1005", demo_password("EMP-1005"))
    con = sqlite3.connect(live.directory / "runtime.db", timeout=1)
    con.execute("BEGIN IMMEDIATE")
    try:
        blocked = requests.get(f"{live.url}/api/portal/profile", headers=employee, timeout=30)
    finally:
        con.rollback()
        con.close()
    assert blocked.status_code == 503 and blocked.headers.get("Retry-After")
    assert "locked" not in blocked.text.lower() and "sqlite" not in blocked.text.lower()
    assert requests.get(f"{live.url}/api/portal/profile", headers=employee, timeout=15).status_code == 200
    assert requests.get(f"{live.url}/api/health", timeout=10).status_code == 200
