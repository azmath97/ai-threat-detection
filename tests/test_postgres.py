"""PostgreSQL integration, run against an embedded PostgreSQL 16 server (the `pgserver` package, see requirements-dev.txt).
The whole module is skipped when pgserver is not installed. Every test talks to a real backend process over HTTP; nothing is
mocked, and the SQLite-only tests in test_persistence.py are not repeated here."""
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import requests
from test_runtime import ADMIN_PASSWORD, EMPLOYEE_PASSWORD, Backend, _free_port

pgserver = pytest.importorskip("pgserver")
psycopg = pytest.importorskip("psycopg")

from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from backend import migrations  # noqa: E402
from backend.database import Base  # noqa: E402
from backend.db_tools import CopyError, copy_database, count_rows, make_engine  # noqa: E402
from backend.models import AuditLog  # noqa: E402

BIN = Path(pgserver.__file__).parent / "pginstall" / "bin"


class Postgres:
    """A throw-away PostgreSQL server on a fixed local port, so it can be stopped and started again at the same address."""

    def __init__(self, directory: Path):
        self.data = directory / "data"
        self.log = directory / "postgres.log"
        self.port = _free_port()

    def _run(self, program: str, *args: str, quiet: bool = False) -> None:
        # pg_ctl's server inherits output pipes; send them to the null device so the call returns when pg_ctl does
        kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL} if quiet else {"capture_output": True}
        result = subprocess.run([str(BIN / program), *args], timeout=120, **kwargs)
        assert result.returncode == 0, f"{program} failed: {getattr(result, 'stderr', b'')[-400:]}"

    def init(self) -> None:
        self._run("initdb", "-D", str(self.data), "-U", "postgres", "--auth=trust", "-E", "UTF8", "--no-sync")

    def start(self) -> None:
        self._run("pg_ctl", "-D", str(self.data), "-o", f"-p {self.port} -c listen_addresses=127.0.0.1 -c fsync=off",
                  "-l", str(self.log), "-w", "start", quiet=True)

    def stop(self) -> None:
        self._run("pg_ctl", "-D", str(self.data), "-m", "fast", "-w", "stop", quiet=True)

    def create_database(self, name: str) -> str:
        with psycopg.connect(f"postgresql://postgres@127.0.0.1:{self.port}/postgres", autocommit=True) as conn:
            conn.execute(f'CREATE DATABASE "{name}"')
        return self.url(name)

    def url(self, name: str) -> str:
        return f"postgresql://postgres@127.0.0.1:{self.port}/{name}"


@pytest.fixture(scope="module")
def pg(tmp_path_factory):
    server = Postgres(tmp_path_factory.mktemp("pg"))
    server.init()
    server.start()
    yield server
    try:
        server.stop()
    except AssertionError:
        pass                                                                  # already stopped by a test


def _backend(directory: Path, url: str) -> Backend:
    backend = Backend(directory)
    backend.env.update(DATABASE_URL=url, RATE_LIMIT_SENSITIVE_PER_MINUTE="100000", RATE_LIMIT_HEAVY_PER_MINUTE="100000",
                       RATE_LIMIT_EMPLOYEE_PER_MINUTE="100000")
    return backend


@pytest.fixture(scope="module")
def api(pg, tmp_path_factory):
    backend = _backend(tmp_path_factory.mktemp("pgapi"), pg.create_database("westbridge"))
    backend.start()
    yield backend
    backend.stop()


def _admin(api):
    return api.login("SEC-9011", ADMIN_PASSWORD)


def _new_events(api, admin, mark, **filters):
    return [r for r in api.get("/api/soc/events", admin, limit=300, **filters)["rows"] if r["id"] > mark]


def test_the_backend_creates_migrates_and_seeds_a_postgresql_database(api):
    info = api.get("/api/system/database", _admin(api))
    assert info["dialect"] == "postgresql" and info["driver"] == "psycopg" and info["persistent_shared_store"] is True
    assert info["schema_version"] == info["latest_schema_version"] == migrations.CURRENT_VERSION
    assert info["row_counts"]["employees"] >= 10 and info["row_counts"]["security_events"] > 100
    assert info["url"].startswith("postgresql+psycopg://") and "password" not in str(info).lower()


def test_every_index_and_constraint_exists_in_postgresql(pg):
    expected_indexes = {i.name for t in Base.metadata.sorted_tables for i in t.indexes}
    expected_checks = {c.name for t in Base.metadata.sorted_tables for c in t.constraints if c.__class__.__name__ == "CheckConstraint"}
    with psycopg.connect(pg.url("westbridge")) as conn:
        indexes = {r[0] for r in conn.execute("SELECT indexname FROM pg_indexes WHERE schemaname = 'public'")}
        checks = {r[0] for r in conn.execute("SELECT conname FROM pg_constraint WHERE contype = 'c'")}
        partial = conn.execute("SELECT indexdef FROM pg_indexes WHERE indexname = 'uq_alerts_one_open_per_employee'").fetchone()[0]
        versions = [r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
    assert expected_indexes <= indexes and expected_checks <= checks
    assert "WHERE" in partial and "open" in partial                           # a real partial unique index, not a plain one
    assert versions == list(range(1, migrations.CURRENT_VERSION + 1))


def test_concurrent_requests_with_one_idempotency_key_store_one_event(api):
    admin, alice = _admin(api), api.login("EMP-1001", EMPLOYEE_PASSWORD)
    mark = api.get("/api/soc/events", admin, limit=1)["latest_id"]
    key, barrier = "pg-race-key-0000000001", threading.Barrier(16)

    def hit(_):
        barrier.wait()
        return requests.get(f"{api.url}/api/portal/profile", headers={**alice, "Idempotency-Key": key}, timeout=60).status_code

    with ThreadPoolExecutor(16) as pool:
        statuses = list(pool.map(hit, range(16)))
    assert set(statuses) == {200}
    assert len([r for r in _new_events(api, admin, mark, employee="EMP-1001") if r["resource"] == "my-profile"]) == 1


def test_concurrent_requests_with_different_keys_are_all_stored(api):
    admin, carol = _admin(api), api.login("EMP-1003", demo_password("EMP-1003"))
    mark = api.get("/api/soc/events", admin, limit=1)["latest_id"]

    def hit(i):
        return requests.get(f"{api.url}/api/portal/profile", headers={**carol, "Idempotency-Key": f"pg-distinct-key-{i:08d}"}, timeout=60).status_code

    with ThreadPoolExecutor(16) as pool:
        statuses = list(pool.map(hit, range(16)))
    assert set(statuses) == {200}
    assert len([r for r in _new_events(api, admin, mark, employee="EMP-1003") if r["resource"] == "my-profile"]) == 16


def test_simultaneous_attack_steps_leave_one_live_alert_and_one_live_investigation(api):
    admin = _admin(api)
    david = next(e["id"] for e in api.get("/api/employees", admin) if e["username"] == "david.kumar")
    steps = ["unfamiliar_login", "restricted_access", "large_export"]

    def attack(_):
        return [requests.post(f"{api.url}/api/simulation/steps", headers=admin, timeout=60, json={
            "target_employee_id": david, "step": s, "source_ip": "185.220.101.45", "scenario": "it_admin_full_chain"}).status_code
            for s in steps]

    with ThreadPoolExecutor(6) as pool:
        results = list(pool.map(attack, range(6)))
    assert all(code < 500 for codes in results for code in codes), results
    alerts = [a for a in api.get("/api/alerts", admin, employee_id=david) if a["status"] in ("open", "investigating")]
    cases = [c for c in api.get("/api/soc/investigations", admin, status="active") if c["employee_pk"] == david]
    assert len(alerts) == 1 and len(cases) == 1


def test_data_persists_across_a_backend_restart_on_postgresql(api):
    admin = _admin(api)
    before = api.get("/api/system/database", admin)["row_counts"]
    api.stop()
    api.start()
    admin = _admin(api)
    after = api.get("/api/system/database", admin)["row_counts"]
    assert all(after[k] >= v for k, v in before.items()) and after["employees"] == before["employees"]   # nothing reseeded or lost


def test_the_database_is_copied_from_sqlite_to_postgresql_and_the_copy_is_usable(pg, tmp_path):
    source_backend = Backend(tmp_path / "sqlite-src")
    source_backend.directory.mkdir()
    source_backend.start()
    source_backend.stop()
    source = f"sqlite:///{(source_backend.directory / 'runtime.db').as_posix()}"
    target = pg.create_database("copy_target")
    expected = count_rows(make_engine(source))

    report = copy_database(source, target, batch=200)
    assert report.rows == expected and report.target_version == migrations.CURRENT_VERSION
    with pytest.raises(CopyError, match="already holds rows"):
        copy_database(source, target)

    engine = make_engine(target)
    with Session(engine) as s:                                                # sequences were moved past the copied ids
        s.add(AuditLog(action="after_copy", target_type="database", details={}))
        s.commit()
        assert s.scalar(select(AuditLog.id).where(AuditLog.action == "after_copy")) > expected["audit_logs"]
        assert s.scalar(select(AuditLog.id).order_by(AuditLog.id.desc())) == s.scalar(select(AuditLog.id).where(AuditLog.action == "after_copy"))

    copy_backend = _backend(tmp_path / "copy-api", target)
    copy_backend.directory.mkdir()
    copy_backend.start()                                                      # starts on the copy without reseeding
    try:
        admin = copy_backend.login("SEC-9011", ADMIN_PASSWORD)
        copy_backend.login("EMP-1001", EMPLOYEE_PASSWORD)                     # the copied password hashes work
        counts = copy_backend.get("/api/system/database", admin)["row_counts"]
        assert counts["employees"] == expected["employees"] and counts["security_events"] >= expected["security_events"]
    finally:
        copy_backend.stop()


def test_a_database_outage_gives_503_without_details_and_the_backend_recovers_by_itself(api, pg):
    admin = _admin(api)
    assert api.get("/api/soc/overview", admin)["kpis"]["total_events"] > 0
    pg.stop()
    try:
        health = requests.get(f"{api.url}/api/health", timeout=40)
        overview = requests.get(f"{api.url}/api/soc/overview", headers=admin, timeout=40)
        for response in (health, overview):
            assert response.status_code == 503, response.text
            assert "psycopg" not in response.text and "127.0.0.1" not in response.text and str(pg.port) not in response.text
    finally:
        pg.start()
    deadline = time.time() + 60
    while time.time() < deadline:                                             # no backend restart: its pool reconnects
        try:
            if requests.get(f"{api.url}/api/health", timeout=10).status_code == 200:
                break
        except requests.RequestException:
            pass
        time.sleep(0.5)
    else:
        pytest.fail("the backend did not recover after the database came back")
    assert requests.get(f"{api.url}/api/soc/overview", headers=admin, timeout=30).status_code == 200   # the old session still works


def demo_password(identifier):
    from data.demo_accounts import demo_password as lookup

    return lookup(identifier)
