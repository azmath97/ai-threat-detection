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

from backend.config import get_settings  # noqa: E402
from backend.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def db_path():
    return Path(_tmp, "test.db")


def login(client, identifier, password=None, headers=None):
    """`identifier` is an employee ID (EMP-1001) or a username."""
    s = get_settings()
    is_admin = identifier in ("soc.admin", "SEC-9011")
    password = password or (s.demo_admin_password if is_admin else s.demo_employee_password)
    return client.post("/api/auth/login", json={"employee_id": identifier, "password": password}, headers=headers or {})


def auth_header(client, identifier):
    response = login(client, identifier)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin(client):
    return auth_header(client, "SEC-9011")
