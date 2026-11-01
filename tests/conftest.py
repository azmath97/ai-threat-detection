import os
import sys
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="itd_test_")
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_tmp, 'test.db').as_posix()}"
os.environ["AUTO_SEED"] = "true"
os.environ["PASSWORD_HASH_ITERATIONS"] = "1000"
os.environ["SECRET_KEY"] = "test-secret"
os.environ["ML_MODEL_PATH"] = str(Path(_tmp, "isolation_forest.joblib"))  # exercises train-on-first-start
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from backend.main import app  # noqa: E402
from data.demo_accounts import demo_password  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def db_path():
    return Path(_tmp, "test.db")


def login(client, identifier, password=None, headers=None):
    """`identifier` is an employee ID (EMP-1001) or a username."""
    password = password or demo_password(identifier, default="No-Such-Account#1")
    return client.post("/api/auth/login", json={"employee_id": identifier, "password": password}, headers=headers or {})


def auth_header(client, identifier):
    response = login(client, identifier)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin(client):
    return auth_header(client, "SEC-9011")


@pytest.fixture(autouse=True)
def restore_state(request):
    """Reset the simulation and delete the real rows a test created, so every test starts from the seeded baseline."""
    if "client" not in request.fixturenames and "admin" not in request.fixturenames:
        yield                                                       # pure unit tests never touch the application database
        return
    import sqlite3

    client, admin, db_path = (request.getfixturevalue(n) for n in ("client", "admin", "db_path"))
    tables = ("security_events", "risk_assessments", "security_alerts", "attack_investigations")
    with sqlite3.connect(db_path) as con:
        marks = {t: con.execute(f"select coalesce(max(id), 0) from {t}").fetchone()[0] for t in tables}
    yield
    client.post("/api/simulation/reset", headers=admin)
    with sqlite3.connect(db_path) as con:
        con.execute("delete from investigation_evidence where investigation_id > ?", (marks["attack_investigations"],))
        for table in ("security_alerts", "attack_investigations", "risk_assessments", "security_events"):
            con.execute(f"delete from {table} where id > ?", (marks[table],))
