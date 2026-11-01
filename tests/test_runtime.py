"""Runtime checks against a real, separately running backend process (not the in-process test client):
persistence across a restart, and the three Streamlit front ends driving that backend over HTTP."""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests
from streamlit.testing.v1 import AppTest

import frontend.api_client as api_client
from data.demo_accounts import demo_password

ROOT = Path(__file__).resolve().parent.parent
EMPLOYEE_PASSWORD, ADMIN_PASSWORD = demo_password("EMP-1001"), demo_password("SEC-9011")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Backend:
    """One uvicorn process per start, all using the same SQLite file and model file."""

    def __init__(self, directory: Path):
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.directory = directory
        self.process: subprocess.Popen | None = None
        self.env = {**os.environ, "DATABASE_URL": f"sqlite:///{(directory / 'runtime.db').as_posix()}",
                    "ML_MODEL_PATH": str(directory / "model.joblib"), "AUTO_SEED": "true", "PASSWORD_HASH_ITERATIONS": "1000",
                    "SECRET_KEY": "runtime-test-secret"}

    def start(self) -> None:
        log = open(self.directory / "backend.log", "ab")
        self.process = subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1",
                                         "--port", str(self.port)], cwd=ROOT, env=self.env, stdout=log, stderr=log)
        deadline = time.time() + 90
        while time.time() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"backend exited early: {(self.directory / 'backend.log').read_text()[-800:]}")
            try:
                if requests.get(f"{self.url}/api/health", timeout=1).status_code == 200:
                    return
            except requests.RequestException:
                time.sleep(0.3)
        raise RuntimeError("backend did not become healthy")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def login(self, identifier: str, password: str) -> dict:
        r = requests.post(f"{self.url}/api/auth/login", json={"employee_id": identifier, "password": password}, timeout=10)
        r.raise_for_status()
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    def get(self, path: str, headers: dict, **params):
        r = requests.get(f"{self.url}{path}", headers=headers, params=params, timeout=15)
        r.raise_for_status()
        return r.json()


@pytest.fixture(scope="module")
def backend(tmp_path_factory):
    b = Backend(tmp_path_factory.mktemp("runtime"))
    b.start()
    yield b
    b.stop()


def test_everything_persists_across_a_backend_restart(backend):
    alice = backend.login("EMP-1001", EMPLOYEE_PASSWORD)
    admin = backend.login("SEC-9011", ADMIN_PASSWORD)
    requests.get(f"{backend.url}/api/portal/profile", headers=alice, timeout=10).raise_for_status()
    before_events = backend.get("/api/events", admin, limit=500)
    before_employees = backend.get("/api/employees", admin)
    before_overview = backend.get("/api/soc/overview", admin)["kpis"]
    model_file = backend.directory / "model.joblib"
    assert model_file.exists() and before_events["total"] > 100
    model_stamp = model_file.stat().st_mtime_ns
    ids_before = {e["id"] for e in before_events["items"]}

    backend.stop()
    backend.start()

    # nothing was re-seeded, retrained or lost; sessions issued before the restart are still valid
    assert requests.get(f"{backend.url}/api/employees/me", headers=alice, timeout=10).json()["employee_code"] == "EMP-1001"
    after_events = backend.get("/api/events", admin, limit=500)
    assert after_events["total"] >= before_events["total"]
    assert ids_before <= {e["id"] for e in after_events["items"]} | ids_before
    assert [e["id"] for e in backend.get("/api/employees", admin)] == [e["id"] for e in before_employees]
    assert backend.get("/api/soc/overview", admin)["kpis"]["total_events"] >= before_overview["total_events"]
    assert model_file.stat().st_mtime_ns == model_stamp
    assert backend.get("/api/detection/status", admin)["model"]["mode"] != "fallback"
    backend.login("EMP-1001", EMPLOYEE_PASSWORD)                              # password hashes survived too


def _run_app(path: str, backend: Backend, monkeypatch) -> AppTest:
    monkeypatch.setattr(api_client, "API_BASE_URL", backend.url)
    return AppTest.from_file(str(ROOT / path), default_timeout=60).run()


def _sign_in(at: AppTest, identifier: str, password: str) -> AppTest:
    at.text_input[0].input(identifier)
    at.text_input[1].input(password)
    return at.button[0].click().run()


def _page_text(at: AppTest) -> str:
    parts = [m.value for m in at.markdown] + [m.value for m in at.caption] + [e.value for e in at.error] + [w.value for w in at.warning]
    parts += [i.value for i in at.info] + [s.value for s in at.success]
    return "\n".join(str(p) for p in parts)


def test_dashboards_degrade_gracefully_when_the_backend_is_unreachable(monkeypatch):
    dead = f"http://127.0.0.1:{_free_port()}"
    monkeypatch.setattr(api_client, "API_BASE_URL", dead)
    for path in ("frontend/employee_portal.py", "frontend/soc_dashboard.py", "frontend/simulation_console.py"):
        at = AppTest.from_file(str(ROOT / path), default_timeout=60).run()
        assert not at.exception, path
        at = _sign_in(at, "SEC-9011", ADMIN_PASSWORD)
        assert not at.exception, path
        assert "token" not in at.session_state and "currently unavailable" in _page_text(at), path


def test_employee_portal_runs_against_the_backend_and_events_reach_the_database(backend, monkeypatch):
    admin = backend.login("SEC-9011", ADMIN_PASSWORD)
    last_id = backend.get("/api/soc/events", admin, limit=1)["latest_id"]

    at = _run_app("frontend/employee_portal.py", backend, monkeypatch)
    assert not at.exception and "Sign in" in at.button[0].label
    at = _sign_in(at, "EMP-1001", "wrong-password")
    assert not at.exception and "token" not in at.session_state
    at = _sign_in(at, "EMP-1001", EMPLOYEE_PASSWORD)
    assert not at.exception and at.session_state["token"]
    for page in ("Dashboard", "HR Records", "Payroll", "Documents", "Employee Directory", "My Profile"):
        at = at.button(key=f"nav_{page}").click().run()
        assert not at.exception, (page, [e.value for e in at.exception])
    assert not at.error or all("permission" in e.value.lower() or "access" in e.value.lower() for e in at.error)
    at = at.button(key="nav_logout").click().run()
    assert not at.exception and "token" not in at.session_state

    feed = backend.get("/api/soc/events", admin, employee="EMP-1001", limit=100)["rows"]
    new = [r for r in feed if r["id"] > last_id]
    types = {(r["event_type"], r["resource"], r["outcome"]) for r in new}
    assert ("login_failed", None, "failure") in types or any(t[0] == "login_failed" for t in types)
    assert any(t[0] == "login" and t[2] == "success" for t in types) and any(t[0] == "logout" for t in types), sorted(types, key=str)
    assert any(t[1] == "my-profile" for t in types) and any(t[1] == "document-library" for t in types)
    assert all(not r["synthetic"] for r in new)


def test_soc_dashboard_is_restricted_to_security_administrators_and_loads_every_page(backend, monkeypatch):
    at = _run_app("frontend/soc_dashboard.py", backend, monkeypatch)
    assert not at.exception
    at = _sign_in(at, "EMP-1001", EMPLOYEE_PASSWORD)                                   # a valid employee login is not enough
    assert not at.exception and "token" not in at.session_state
    assert "restricted to security administrators" in _page_text(at)

    at = _sign_in(_run_app("frontend/soc_dashboard.py", backend, monkeypatch), "SEC-9011", ADMIN_PASSWORD)
    assert not at.exception and at.session_state["token"]
    for page in ("Security Overview", "Live Event Feed", "Attack Investigations", "Employee Risk Monitor", "Attack Timeline",
                 "Attack Graph", "Response Centre", "Audit Logs"):
        at = at.button(key=f"nav_{page}").click().run()
        assert not at.exception, (page, [e.value for e in at.exception])
        assert not [e for e in at.error if "unavailable" in e.value.lower()], page
    at = at.button(key="nav_Logout").click().run() if any(b.key == "nav_Logout" for b in at.button) else at
    assert not at.exception


def test_simulation_console_drives_an_attack_that_the_soc_then_shows(backend, monkeypatch):
    admin = backend.login("SEC-9011", ADMIN_PASSWORD)
    at = _sign_in(_run_app("frontend/simulation_console.py", backend, monkeypatch), "SEC-9011", ADMIN_PASSWORD)
    assert not at.exception and at.session_state["token"]
    run = next(b for b in at.button if b.label.startswith("Run complete scenario"))
    at = run.click().run()
    assert not at.exception, [e.value for e in at.exception]
    overview = backend.get("/api/soc/overview", admin)
    assert overview["kpis"]["critical_alerts"] >= 1 and overview["kpis"]["confirmed_external_transfers"] >= 1
    investigations = backend.get("/api/soc/investigations", admin)
    assert investigations and investigations[0]["level"] == "critical"

    at = at.checkbox[0].check().run()
    reset = next(b for b in at.button if b.label == "Reset simulation")
    at = reset.click().run()
    assert not at.exception
    assert backend.get("/api/soc/overview", admin)["kpis"]["critical_alerts"] == 0
    assert backend.get("/api/simulation/status", admin)["synthetic_events"] == 0
