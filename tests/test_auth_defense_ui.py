"""The SOC "Authentication Defence" page, driven against a real backend process: real failed sign-ins in, incident and response out,
and an analyst unlocking the account through the page (no simulation involved)."""
import pytest
import requests
from test_runtime import ADMIN_PASSWORD, Backend, _page_text, _run_app, _sign_in

KEY = "ui-test-frontend-key-0123456789abcdef"


@pytest.fixture(scope="module")
def backend(tmp_path_factory):
    b = Backend(tmp_path_factory.mktemp("auth_ui"))
    b.env["TRUSTED_FRONTEND_KEY"] = KEY
    b.start()
    yield b
    b.stop()


def _attempt(backend, who: str, password: str, ip: str) -> requests.Response:
    return requests.post(f"{backend.url}/api/auth/login", json={"employee_id": who, "password": password},
                         headers={"X-Frontend-Key": KEY, "X-Client-IP": ip}, timeout=15)


def test_an_analyst_sees_a_real_attack_and_recovers_the_account_through_the_page(backend, monkeypatch):
    admin = backend.login("SEC-9011", ADMIN_PASSWORD)
    for _ in range(5):
        assert _attempt(backend, "EMP-1001", "wrong-password-0000", "203.0.113.20").status_code == 401
    overview = backend.get("/api/soc/auth/overview", admin)
    assert [a["employee_id"] for a in overview["locked_accounts"]] == ["EMP-1001"]

    at = _sign_in(_run_app("frontend/soc_dashboard.py", backend, monkeypatch), "SEC-9011", ADMIN_PASSWORD)
    assert not at.exception, [e.value for e in at.exception]
    at = at.button(key="nav_Authentication Defence").click().run()
    assert not at.exception, [e.value for e in at.exception]
    text = _page_text(at)
    assert "Authentication Defence" in text and "not firewall rules" in text
    assert "Repeated failed sign-ins against EMP-1001" in " ".join(str(m.value) for m in at.markdown)
    assert "simulat" not in text.lower()                                       # real data, real responses: nothing here is a simulation
    assert "Unlock" in [b.label for b in at.button]

    at = at.button(key="unlock_EMP-1001").click().run()
    assert "Confirm: Unlock account" in " ".join(str(m.value) for m in at.markdown) or "Confirm: Unlock account" in _page_text(at)
    at = at.button(key="auth_go").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert backend.get("/api/soc/auth/overview", admin)["locked_accounts"] == []
    done = [a for a in backend.get("/api/soc/auth/actions", admin)["rows"] if a["action"] == "unlock_account"]
    assert done and done[0]["status"] == "completed" and not done[0]["automatic"] and done[0]["performed_by"] == "SEC-9011"
