"""Deployment: start-up validation, the public gateway, and the deployment files (Dockerfile, render.yaml, requirements).

Nothing here talks to a hosting platform. The gateway is exercised against a throw-away fake upstream on loopback.
"""
import ast
import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocket

from deploy import gateway, make_secrets, preflight
from deploy.gateway import GATE_COOKIE, GatewayConfig

ROOT = Path(__file__).resolve().parent.parent
DEMO = make_secrets.make()


def good_env(**overrides) -> dict[str, str]:
    env = {
        "DEPLOY_MODE": "persistent", "DATABASE_URL": "postgresql://user:pw@db.example.test:5432/app",
        "SECRET_KEY": DEMO["SECRET_KEY"], "PUBLIC_URL": "https://demo.westbridge.test",
        "ADMIN_UI_USER": DEMO["ADMIN_UI_USER"], "ADMIN_UI_PASSWORD": DEMO["ADMIN_UI_PASSWORD"],
        "DEMO_PASSWORDS_JSON": DEMO["DEMO_PASSWORDS_JSON"],
    }
    env.update(overrides)
    return {k: v for k, v in env.items() if v is not None}


# ------------------------------------------------------------------------------------------------- start-up validation
def test_a_complete_configuration_has_no_problems():
    assert preflight.problems(good_env()) == []


@pytest.mark.parametrize("name", ["DATABASE_URL", "SECRET_KEY", "PUBLIC_URL", "ADMIN_UI_USER", "ADMIN_UI_PASSWORD", "DEMO_PASSWORDS_JSON"])
def test_every_missing_required_setting_is_reported_by_name(name):
    found = preflight.problems(good_env(**{name: None}))
    assert found and any(name in problem for problem in found)


def test_render_supplies_the_public_url():
    env = good_env(PUBLIC_URL=None, RENDER_EXTERNAL_URL="https://westbridge.onrender.com")
    assert preflight.problems(env) == []
    assert preflight.child_environment(env)["CORS_ORIGINS"] == "https://westbridge.onrender.com"


def test_persistent_mode_refuses_sqlite_and_demo_mode_refuses_a_database_url():
    assert any("PostgreSQL" in p for p in preflight.problems(good_env(DATABASE_URL="sqlite:///./x.db")))
    found = preflight.problems(good_env(DEPLOY_MODE="demo"))
    assert any("DATABASE_URL is set but DEPLOY_MODE=demo" in p for p in found)
    assert preflight.problems(good_env(DEPLOY_MODE="demo", DATABASE_URL=None)) == []


def test_unknown_mode_is_rejected():
    assert any("DEPLOY_MODE" in p for p in preflight.problems(good_env(DEPLOY_MODE="staging")))


@pytest.mark.parametrize("secret", ["", "short", "change-me-" + "x" * 40, "secret" + "y" * 40])
def test_weak_or_placeholder_secret_keys_are_refused(secret):
    assert any("SECRET_KEY" in p for p in preflight.problems(good_env(SECRET_KEY=secret)))


@pytest.mark.parametrize("url", ["http://demo.westbridge.test", "https://demo.westbridge.test/path", "https://*.example.test", "ftp://x"])
def test_public_url_must_be_a_plain_https_origin(url):
    assert any("PUBLIC_URL" in p for p in preflight.problems(good_env(PUBLIC_URL=url)))


def test_plain_http_is_accepted_for_localhost_only():
    assert preflight.problems(good_env(PUBLIC_URL="http://127.0.0.1:8080")) == []


def test_the_admin_gate_needs_a_long_password_unless_explicitly_opened():
    assert any("ADMIN_UI_PASSWORD" in p for p in preflight.problems(good_env(ADMIN_UI_PASSWORD="short-pass")))
    assert preflight.problems(good_env(ADMIN_UI_USER=None, ADMIN_UI_PASSWORD=None, ALLOW_OPEN_ADMIN_UI="true")) == []


def test_demo_passwords_must_be_valid_json_for_every_account():
    assert any("not valid JSON" in p for p in preflight.problems(good_env(DEMO_PASSWORDS_JSON="{nope")))
    partial = json.dumps({"alice.morgan": "Another-Strong-Password-1"})
    assert any("DEMO_PASSWORDS_JSON" in p for p in preflight.problems(good_env(DEMO_PASSWORDS_JSON=partial)))


def test_problems_never_contain_secret_values():
    env = good_env(SECRET_KEY="short", ADMIN_UI_PASSWORD="tiny", DATABASE_URL="mysql://user:hunter2-password@db/app",
                   DEMO_PASSWORDS_JSON="{broken-" + DEMO["ADMIN_UI_PASSWORD"])
    text = "\n".join(preflight.problems(env))
    for value in ("hunter2-password", "short", "tiny", DEMO["ADMIN_UI_PASSWORD"], env["DATABASE_URL"]):
        assert value not in text


def test_child_environment_is_production_with_private_loopback_api():
    child = preflight.child_environment(good_env())
    assert child["APP_ENV"] == "production" and child["API_BASE_URL"] == "http://127.0.0.1:8000"
    assert child["CORS_ORIGINS"] == "https://demo.westbridge.test" == child["STREAMLIT_SERVER_CORS_ALLOWED_ORIGINS"]
    assert child["REQUIRE_HTTPS"] == "true" and child["FORCE_HTTPS"] == "true" and child["MAP_LOOPBACK_TO_WORKSTATION"] == "true"
    assert child["ENABLE_API_DOCS"] == "false" and child["DATABASE_URL"].startswith("postgresql://")
    assert "ALLOW_SQLITE_IN_PRODUCTION" not in child


def test_demo_mode_uses_its_own_disposable_sqlite_file(tmp_path):
    child = preflight.child_environment(good_env(DEPLOY_MODE="demo", DATABASE_URL=None, DEMO_DB_DIR=str(tmp_path)))
    assert child["DATABASE_URL"] == f"sqlite:///{(tmp_path / 'demo.db').as_posix()}"
    assert child["ALLOW_SQLITE_IN_PRODUCTION"] == "true"


def test_the_dashboards_refuse_to_start_in_production_without_an_api_url(monkeypatch):
    from frontend import api_client

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("API_BASE_URL", raising=False)
    with pytest.raises(RuntimeError):
        api_client._api_base_url()
    monkeypatch.setenv("API_BASE_URL", "http://127.0.0.1:8000")
    assert api_client._api_base_url() == "http://127.0.0.1:8000"
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.delenv("API_BASE_URL")
    assert api_client._api_base_url().startswith("http://")


def test_make_secrets_produces_values_that_pass_validation():
    for _ in range(2):
        generated = make_secrets.make()
        assert len(generated["SECRET_KEY"]) >= 32 and len(generated["ADMIN_UI_PASSWORD"]) >= 16
        assert preflight.problems(good_env(**generated)) == []
    assert make_secrets.make()["SECRET_KEY"] != make_secrets.make()["SECRET_KEY"]


# ------------------------------------------------------------------------------------------------------- the gateway
def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def fake_upstream() -> Starlette:
    async def page(request: Request):
        return JSONResponse({"path": request.url.path, "cookie": request.headers.get("cookie", ""),
                             "forwarded_for": request.headers.get("x-forwarded-for", ""), "method": request.method,
                             "client_ip": request.headers.get("x-westbridge-client-ip", "")})

    async def ok(request: Request):
        return PlainTextResponse("ok")

    async def echo(websocket: WebSocket):
        await websocket.accept()
        async for text in websocket.iter_text():
            await websocket.send_text(f"echo:{text}")

    return Starlette(routes=[
        Route("/api/health", ok), Route("/_stcore/health", ok), Route("/soc/_stcore/health", ok), Route("/console/_stcore/health", ok),
        WebSocketRoute("/{path:path}", echo), Route("/{path:path}", page, methods=["GET", "POST"]),
    ])


@pytest.fixture(scope="module")
def upstream_port():
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(fake_upstream(), host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started
    yield port
    server.should_exit = True
    thread.join(timeout=10)


GATE_USER, GATE_PASSWORD = "gate-user", "a-long-gate-password-1"


def make_cfg(port: int, **overrides) -> GatewayConfig:
    target = f"127.0.0.1:{port}"
    values = {"backend": target, "portal": target, "console": target, "soc": target, "admin_user": GATE_USER,
              "admin_password": GATE_PASSWORD, "gate_key": gateway.hmac.new(b"unit-test-secret-key", b"gate", "sha256").digest()}
    values.update(overrides)
    return GatewayConfig(**values)


def basic(user=GATE_USER, password=GATE_PASSWORD) -> dict:
    return {"authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


@pytest.fixture
def gw(upstream_port):
    with TestClient(gateway.create_app(make_cfg(upstream_port)), client=("203.0.113.7", 5000)) as client:
        yield client


def test_gateway_routes_each_path_to_its_own_application(gw):
    assert gw.get("/").json()["path"] == "/"
    assert gw.get("/soc/", headers=basic()).json()["path"] == "/soc/"
    assert gw.get("/console/", headers=basic()).json()["path"] == "/console/"


def test_the_backend_api_and_its_documentation_are_never_public(gw):
    for path in ("/api/health", "/api/auth/login", "/api", "/docs", "/redoc", "/openapi.json"):
        for method in ("get", "post"):
            assert getattr(gw, method)(path).status_code == 404, (method, path)


def test_admin_pages_need_the_gate_login(gw):
    for path in ("/soc/", "/console/", "/soc/anything"):
        denied = gw.get(path)
        assert denied.status_code == 401 and "Basic" in denied.headers["www-authenticate"]
    assert gw.get("/soc/", headers=basic(password="wrong-password-123456")).status_code == 401
    assert gw.get("/soc/", headers=basic(user="someone-else")).status_code == 401
    assert gw.get("/soc/", headers={"authorization": "Basic !!!not-base64"}).status_code == 401
    assert gw.get("/").status_code == 200                       # the employee portal is public, the backend still requires sign-in


def test_a_valid_gate_login_sets_a_signed_cookie_that_is_not_passed_upstream(gw):
    first = gw.get("/soc/", headers=basic(), follow_redirects=False)
    set_cookie = first.headers["set-cookie"].lower()
    assert first.status_code == 200 and GATE_COOKIE in set_cookie and "httponly" in set_cookie and "samesite=strict" in set_cookie
    assert GATE_COOKIE not in first.json()["cookie"]
    again = gw.get("/soc/")                                      # the cookie jar now admits the browser without credentials
    assert again.status_code == 200 and GATE_COOKIE not in again.json()["cookie"]


def test_a_forged_or_tampered_gate_cookie_is_refused(upstream_port):
    cfg = make_cfg(upstream_port)
    with TestClient(gateway.create_app(cfg)) as client:
        issued = int(time.time())
        for forged in (f"{issued}.{'0' * 64}", "garbage", f"{issued - 10 * 3600}.{gateway._sign(cfg, issued - 10 * 3600).split('.')[1]}"):
            client.cookies.clear()
            client.cookies.set(GATE_COOKIE, forged)
            assert client.get("/soc/").status_code == 401, forged
        client.cookies.clear()
        client.cookies.set(GATE_COOKIE, gateway._sign(cfg, issued))
        assert client.get("/soc/").status_code == 200


def test_gate_failures_are_throttled_per_client(upstream_port):
    cfg = make_cfg(upstream_port, max_gate_failures=3)
    with TestClient(gateway.create_app(cfg), client=("203.0.113.9", 1)) as client:
        for _ in range(3):
            assert client.get("/soc/", headers=basic(password="wrong-password-123456")).status_code == 401
        blocked = client.get("/soc/", headers=basic())            # even the right password waits out the window
        assert blocked.status_code == 429 and "retry-after" in blocked.headers
    with TestClient(gateway.create_app(cfg), client=("203.0.113.10", 1)) as other:
        assert other.get("/soc/", headers=basic()).status_code == 200


def test_the_first_unauthenticated_challenge_is_not_counted_as_a_failure(upstream_port):
    cfg = make_cfg(upstream_port, max_gate_failures=2)
    with TestClient(gateway.create_app(cfg)) as client:
        for _ in range(5):
            assert client.get("/soc/").status_code == 401
        assert client.get("/soc/", headers=basic()).status_code == 200


def test_the_gate_can_only_be_removed_explicitly(upstream_port):
    with TestClient(gateway.create_app(make_cfg(upstream_port, allow_open_admin=True))) as client:
        assert client.get("/soc/").status_code == 200
    with TestClient(gateway.create_app(make_cfg(upstream_port, admin_user="", admin_password=""))) as client:
        assert client.get("/soc/", headers=basic("", "")).status_code == 401


def test_requests_are_forwarded_with_the_client_address_and_security_headers(gw):
    response = gw.post("/", content=b"x", headers={"x-forwarded-proto": "https"})
    assert response.status_code == 200 and response.json()["method"] == "POST"
    assert response.json()["forwarded_for"].endswith("203.0.113.7")
    assert response.headers["x-content-type-options"] == "nosniff" and response.headers["x-frame-options"] == "SAMEORIGIN"
    assert "strict-transport-security" in response.headers
    assert "strict-transport-security" not in gw.get("/").headers


def test_force_https_redirects_plain_http_only(upstream_port):
    with TestClient(gateway.create_app(make_cfg(upstream_port, force_https=True))) as client:
        redirect = client.get("/?x=1", follow_redirects=False)
        assert redirect.status_code == 308 and redirect.headers["location"].startswith("https://") and redirect.headers["location"].endswith("/?x=1")
        assert client.get("/", headers={"x-forwarded-proto": "https"}).status_code == 200


def test_healthz_reports_every_component_and_a_failure(upstream_port, gw):
    ok = gw.get("/healthz")
    assert ok.status_code == 200 and ok.json()["status"] == "ok" and set(ok.json()["components"]) == {"backend", "portal", "console", "soc"}
    dead = make_cfg(upstream_port, soc=f"127.0.0.1:{free_port()}")
    with TestClient(gateway.create_app(dead)) as client:
        down = client.get("/healthz")
        assert down.status_code == 503 and down.json()["components"]["soc"] == "down" and down.json()["components"]["portal"] == "ok"


def test_an_unavailable_application_gives_a_generic_502(upstream_port):
    cfg = make_cfg(upstream_port, portal=f"127.0.0.1:{free_port()}")
    with TestClient(gateway.create_app(cfg)) as client:
        response = client.get("/")
        assert response.status_code == 502 and "127.0.0.1" not in response.text and "Traceback" not in response.text


def test_websockets_are_proxied_and_admin_sockets_need_the_gate(upstream_port):
    cfg = make_cfg(upstream_port)
    with TestClient(gateway.create_app(cfg)) as client:
        with client.websocket_connect("/_stcore/stream") as ws:
            ws.send_text("hello")
            assert ws.receive_text() == "echo:hello"
        with pytest.raises(Exception):                                  # closed with 4401 before the upgrade completes
            with client.websocket_connect("/soc/_stcore/stream") as ws:
                ws.send_text("hello")
                ws.receive_text()
        client.cookies.set(GATE_COOKIE, gateway._sign(cfg, int(time.time())))
        with client.websocket_connect("/soc/_stcore/stream") as ws:
            ws.send_text("hi")
            assert ws.receive_text() == "echo:hi"


def test_the_gateway_tells_the_dashboards_the_real_client_address_and_ignores_what_the_browser_claims(upstream_port):
    spoof = {"x-westbridge-client-ip": "198.51.100.99", "x-forwarded-for": "198.51.100.98"}
    with TestClient(gateway.create_app(make_cfg(upstream_port)), client=("203.0.113.7", 5000)) as direct:
        # no platform proxy declared: only the TCP peer is believed, never X-Forwarded-For or a header the browser invented
        assert direct.get("/", headers=spoof).json()["client_ip"] == "203.0.113.7"
    with TestClient(gateway.create_app(make_cfg(upstream_port, trust_forwarded_for=True)), client=("10.0.0.5", 5000)) as behind:
        # behind the platform's proxy: the LAST entry (appended by that proxy) is the client; earlier entries are client-supplied
        seen = behind.get("/", headers={"x-forwarded-for": "198.51.100.98, 203.0.113.44", "x-westbridge-client-ip": "198.51.100.99"})
        assert seen.json()["client_ip"] == "203.0.113.44"
        assert behind.get("/", headers={"x-forwarded-for": "not-an-ip"}).json()["client_ip"] == "10.0.0.5"
        assert behind.get("/").json()["client_ip"] == "10.0.0.5"


def test_the_websocket_handshake_carries_the_client_address(upstream_port):
    cfg = make_cfg(upstream_port)
    assert gateway.trusted_client_ip(cfg, {"x-forwarded-for": "198.51.100.1"}, "203.0.113.7") == "203.0.113.7"
    assert gateway.trusted_client_ip(make_cfg(upstream_port, trust_forwarded_for=True), {"x-forwarded-for": "198.51.100.1"}, "10.0.0.5") == "198.51.100.1"


def test_each_start_gets_its_own_frontend_key_and_forwarded_for_is_trusted_only_on_render():
    first, second = preflight.child_environment(good_env()), preflight.child_environment(good_env())
    assert len(first["TRUSTED_FRONTEND_KEY"]) >= 32 and first["TRUSTED_FRONTEND_KEY"] != second["TRUSTED_FRONTEND_KEY"]
    assert preflight.child_environment(good_env(TRUSTED_FRONTEND_KEY="operator-chosen-key"))["TRUSTED_FRONTEND_KEY"] == "operator-chosen-key"
    assert first["TRUST_FORWARDED_FOR"] == "false"
    assert preflight.child_environment(good_env(RENDER="true"))["TRUST_FORWARDED_FOR"] == "true"


def test_the_dashboards_forward_the_client_address_only_with_the_shared_key(monkeypatch):
    from frontend import api_client

    captured = {}

    class Reply:
        status_code, headers = 200, {}

        @staticmethod
        def json():
            return {}

    def fake_request(method, url, headers=None, **kwargs):
        captured.update(headers or {})
        return Reply()

    monkeypatch.setattr(api_client.requests, "request", fake_request)
    real_browser_ip = api_client._browser_ip
    monkeypatch.setattr(api_client, "_browser_ip", lambda: "203.0.113.55")
    monkeypatch.setattr(api_client, "FRONTEND_KEY", "")
    api_client.ApiClient("token").get("/api/soc/version")
    assert "X-Client-IP" not in captured and "X-Frontend-Key" not in captured          # nothing is sent without the shared key
    captured.clear()
    monkeypatch.setattr(api_client, "FRONTEND_KEY", "shared-key-0123456789")
    api_client.ApiClient("token").get("/api/soc/version")
    assert captured["X-Client-IP"] == "203.0.113.55" and captured["X-Frontend-Key"] == "shared-key-0123456789"
    assert real_browser_ip() is None                                                     # outside a Streamlit run there is no browser


# ------------------------------------------------------------------------------------------------ deployment files
def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_the_dockerfile_builds_the_model_and_runs_unprivileged():
    text = read("Dockerfile")
    assert "requirements-deploy.txt" in text and "python -m ml.train_model" in text
    assert "USER app" in text and 'CMD ["python", "-m", "deploy.start"]' in text and "HEALTHCHECK" in text
    assert "/healthz" in text and "SECRET_KEY" not in text and "PASSWORD" not in text.upper()
    assert "LOCAL_SECRET_FILE=/tmp/" in text           # the build's throw-away key never lands in an image layer
    for line in text.splitlines():
        if line.startswith("COPY "):
            for source in line.split()[1:-1]:
                assert (ROOT / source).exists(), f"Dockerfile copies a missing path: {source}"


def test_the_image_contains_everything_the_application_imports(tmp_path):
    """Copy only what the Dockerfile copies into an empty folder and import every entry point from there."""
    for line in read("Dockerfile").splitlines():
        if not line.startswith("COPY "):
            continue
        *sources, dest = line.split()[1:]
        target = tmp_path / dest.lstrip("./").rstrip("/") if dest not in (".", "./") else tmp_path
        for source in sources:
            src = ROOT / source
            if src.is_dir():
                shutil.copytree(src, tmp_path / source, ignore=shutil.ignore_patterns("__pycache__"), dirs_exist_ok=True)
            else:
                target.mkdir(parents=True, exist_ok=True)
                shutil.copy(src, target / src.name if target.is_dir() or dest.endswith("/") else target)
    code = ("import backend.main, backend.simulation_service, data.seed_data, data.demo_accounts, ml.train_model, ml.anomaly_detector, "
            "deploy.start, deploy.gateway, deploy.preflight, deploy.verify, deploy.make_secrets, os\n"
            "assert os.path.realpath(backend.main.__file__).startswith(os.path.realpath(os.getcwd())); print('imports-ok')")
    env = {**os.environ, "SECRET_KEY": "x" * 40, "DATABASE_URL": f"sqlite:///{(tmp_path / 'scratch.db').as_posix()}",
           "LOCAL_SECRET_FILE": str(tmp_path / "local_secret"), "ML_MODEL_PATH": str(tmp_path / "model.joblib"), "PYTHONPATH": ""}
    result = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0 and "imports-ok" in result.stdout, result.stderr[-1500:]


def test_the_docker_context_excludes_secrets_and_local_data():
    ignored = set(read(".dockerignore").split())
    for pattern in (".env", ".env.*", "data/demo_credentials.local.json", "data/.local_secret", "data/*.db", "data/external",
                    "data/processed", ".git", "tests", "*.pem", "*.key"):
        assert pattern in ignored, pattern


def test_render_blueprint_holds_no_secret_and_no_local_address():
    text = read("render.yaml")
    assert "runtime: docker" in text and "healthCheckPath: /healthz" in text and "plan: 1c-2g" in text
    assert "localhost" not in text and "127.0.0.1" not in text and "generateValue" not in text
    blocks = re.split(r"\n\s+- key: ", text)[1:]
    keys = {block.splitlines()[0].strip(): block for block in blocks}
    for secret in ("DATABASE_URL", "SECRET_KEY", "DEMO_PASSWORDS_JSON", "ADMIN_UI_USER", "ADMIN_UI_PASSWORD"):
        assert "sync: false" in keys[secret], secret
    assert not any(re.search(r"value:\s*\S{20,}", block) for block in blocks)


def test_the_example_environment_file_has_no_real_values_for_deployment_secrets():
    text = read(".env.example")
    for name in ("ADMIN_UI_PASSWORD", "ADMIN_UI_USER", "DEMO_PASSWORDS_JSON", "SECRET_KEY"):
        for line in text.splitlines():
            if line.lstrip("# ").startswith(name + "="):
                assert line.split("=", 1)[1].split("#")[0].strip() == "", line


LOCAL_PACKAGES = {"backend", "frontend", "ml", "data", "deploy", "app", "tests"}
IMPORT_TO_DISTRIBUTION = {"sklearn": "scikit-learn", "dotenv": "python-dotenv", "argon2": "argon2-cffi", "yaml": "pyyaml"}


def pinned_distributions() -> dict[str, str]:
    pins = {}
    for line in read("requirements-deploy.txt").splitlines():
        line = line.split("#")[0].strip()
        if line:
            name, _, version = line.partition("==")
            pins[re.sub(r"\[.*\]", "", name).lower().replace("_", "-")] = version
    return pins


def test_deployment_requirements_are_exact_pins_without_test_packages():
    for line in read("requirements-deploy.txt").splitlines():
        line = line.split("#")[0].strip()
        if line:
            assert re.fullmatch(r"[A-Za-z0-9_.\[\]-]+==\d[\w.]*", line), line
    assert not {"pytest", "pgserver", "ruff", "pytest-cov"} & set(pinned_distributions())


def test_every_third_party_import_of_the_application_is_in_the_deployment_requirements():
    pins = pinned_distributions()
    missing = {}
    for package in sorted(LOCAL_PACKAGES - {"tests"}) + ["app.py"]:
        path = ROOT / package
        files = [path] if path.is_file() else sorted(path.rglob("*.py"))
        for file in files:
            for node in ast.walk(ast.parse(file.read_text(encoding="utf-8"))):
                modules = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module and node.level == 0 else []
                for module in modules:
                    top = module.split(".")[0]
                    if top in sys.stdlib_module_names or top in LOCAL_PACKAGES or top == "__future__":
                        continue
                    if IMPORT_TO_DISTRIBUTION.get(top, top).lower() not in pins:
                        missing.setdefault(top, file.name)
    # imported only inside try/except to report versions (scipy is installed anyway as a dependency of scikit-learn)
    optional = {"pgserver", "scipy"}
    assert not (set(missing) - optional), missing
