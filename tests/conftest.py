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


def login(client, username, password=None, ip=None):
    s = get_settings()
    password = password or (s.demo_admin_password if username == "soc.admin" else s.demo_employee_password)
    body = {"username": username, "password": password}
    if ip:
        body["source_ip"] = ip
    return client.post("/api/auth/login", json=body)


def auth_header(client, username, ip=None):
    response = login(client, username, ip=ip)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin(client):
    return auth_header(client, "soc.admin")
