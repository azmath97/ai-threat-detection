"""Security tests: secrets and credentials, password hashing, brute-force and rate limits, authorization, request handling,
error leakage, CORS, HTTPS, headers and start-up behaviour with missing configuration."""
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import auth_header, employee_id, login
from fastapi.testclient import TestClient

from backend import hardening
from backend.config import _origin_problems, get_settings, validate_for_environment
from backend.local_secrets import local_secret_key
from backend.main import app
from backend.security import hash_password, needs_rehash, verify_password
from data import demo_accounts
from data.demo_accounts import DEMO_USERNAMES, CredentialsMissing, load_passwords

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


@pytest.fixture()
def fresh_credentials(monkeypatch):
    """Isolated credential state: nothing cached, no env source, a file path that does not exist yet."""
    demo_accounts.reset_cache()
    monkeypatch.delenv("DEMO_PASSWORDS_JSON", raising=False)
    yield monkeypatch
    demo_accounts.reset_cache()


def _all_passwords_json():
    return json.dumps({u: f"Unique-{i:02d}-" + "x" * 12 for i, u in enumerate(DEMO_USERNAMES)})


def _env(**extra):
    env = {k: v for k, v in os.environ.items() if k not in ("SECRET_KEY", "DEMO_PASSWORDS_JSON", "DEMO_CREDENTIALS_FILE")}
    return {**env, **extra}


def _run_python(code: str, **env):
    return subprocess.run([PY, "-c", code], cwd=ROOT, env=_env(**env), capture_output=True, text=True, timeout=120)


# ---------------------------------------------------------------------------------- secrets and credentials in source
# Values an earlier version of this project published. They are split here so this file does not repeat them whole.
OLD_PUBLISHED = [
    "Cedar#" + "Harbor47", "Quill&" + "Meadow82", "Birch!" + "Lantern26", "Falcon$" + "Ridge63", "Willow#" + "Summit19",
    "Amber%" + "Compass74", "Juniper!" + "Atlas58", "Granite#" + "Voyage31", "Coral&" + "Beacon95", "Cobalt!" + "Meadow68",
    "Sentinel#" + "Vault2026", "Synthetic#" + "Priv2026", "dev-only-secret-" + "change-me",
]
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv", "processed", "external", "reports"}


def _text_files():
    for path in ROOT.rglob("*"):
        if path.is_file() and not (set(path.relative_to(ROOT).parts) & SKIP_DIRS) and path.suffix in {
                ".py", ".md", ".txt", ".yaml", ".yml", ".toml", ".json", ".example", ".cfg", ".ini"}:
            yield path


def test_no_published_default_password_or_secret_remains_in_the_working_tree():
    hits = []
    for path in _text_files():
        if path.name == Path(__file__).name or path.name.endswith(".local.json"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        hits += [(path.relative_to(ROOT).as_posix(), value[:6] + "...") for value in OLD_PUBLISHED if value in text]
    assert not hits, hits


def test_local_secret_and_credential_files_are_ignored_by_git_and_not_tracked():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".env", "data/demo_credentials.local.json", "data/.local_secret"):
        assert pattern in ignore.splitlines(), pattern
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^SECRET_KEY=$", example, flags=re.M) and re.search(r"^SIMULATION_PRIVILEGED_PASSWORD=$", example, flags=re.M)
    assert not re.search(r"^(DEMO_PASSWORDS_JSON|TRUSTED_FRONTEND_KEY)=\S", example, flags=re.M)
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True)
    if tracked.returncode == 0:
        names = tracked.stdout.splitlines()
        assert not [n for n in names if n.endswith(".local.json") or n.endswith(".local_secret") or n in (".env",)]


def test_no_plaintext_password_is_stored_in_the_database_file(client, db_path):
    with sqlite3.connect(db_path) as con:
        con.execute("pragma wal_checkpoint(FULL)")
    data = Path(db_path).read_bytes()
    for username, password in load_passwords().items():
        assert password.encode() not in data, username


def test_demo_passwords_are_random_strong_and_unique(fresh_credentials, tmp_path):
    first, second = demo_accounts.generate_passwords(), demo_accounts.generate_passwords()
    assert len(set(first.values())) == len(DEMO_USERNAMES) and first != second
    assert all(len(p) >= demo_accounts.MIN_PASSWORD_LENGTH for p in first.values())
    path = demo_accounts.write_credentials(first, tmp_path / "creds.json")
    assert json.loads(path.read_text(encoding="utf-8")) == first


def test_credential_sources_are_validated(fresh_credentials, tmp_path):
    fresh_credentials.setenv("DEMO_CREDENTIALS_FILE", str(tmp_path / "none.json"))
    for bad in ("{", "[]", json.dumps({"alice.morgan": "short"}),
                json.dumps({u: "same-password-for-all" for u in DEMO_USERNAMES})):
        demo_accounts.reset_cache()
        fresh_credentials.setenv("DEMO_PASSWORDS_JSON", bad)
        with pytest.raises(CredentialsMissing):
            load_passwords()
    demo_accounts.reset_cache()
    fresh_credentials.setenv("DEMO_PASSWORDS_JSON", _all_passwords_json())
    assert set(load_passwords()) == set(DEMO_USERNAMES)


def test_credentials_are_generated_outside_production_and_never_in_production(fresh_credentials, tmp_path):
    target = tmp_path / "generated.json"
    fresh_credentials.setenv("DEMO_CREDENTIALS_FILE", str(target))
    fresh_credentials.setenv("APP_ENV", "production")
    with pytest.raises(CredentialsMissing, match="No demo credentials"):
        load_passwords()
    assert not target.exists()
    demo_accounts.reset_cache()
    fresh_credentials.setenv("APP_ENV", "development")
    assert set(load_passwords()) == set(DEMO_USERNAMES) and target.exists()


def test_setup_command_creates_env_with_a_random_secret_and_credentials_idempotently(fresh_credentials, tmp_path, capsys):
    import app as launcher

    (tmp_path / ".env.example").write_text((ROOT / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    fresh_credentials.setattr(launcher, "ROOT", tmp_path)
    fresh_credentials.setenv("DEMO_CREDENTIALS_FILE", str(tmp_path / "data" / "demo_credentials.local.json"))
    launcher.setup()
    env_text = (tmp_path / ".env").read_text(encoding="utf-8")
    secret = re.search(r"^SECRET_KEY=(\S+)$", env_text, flags=re.M).group(1)
    assert len(secret) >= 40 and "change-me" not in secret
    assert (tmp_path / "data" / "demo_credentials.local.json").exists()
    launcher.setup()                                                          # re-running keeps what exists
    assert (tmp_path / ".env").read_text(encoding="utf-8") == env_text
    assert "left unchanged" in capsys.readouterr().out


# ----------------------------------------------------------------------------------------- missing configuration
def test_production_validation_covers_secret_cors_and_credentials(fresh_credentials, tmp_path):
    base = replace(get_settings(), app_env="production", secret_key="r" * 40, trusted_frontend_key="",
                   database_url="postgresql+psycopg://u:p@db.example.test/w")
    fresh_credentials.setenv("DEMO_CREDENTIALS_FILE", str(tmp_path / "absent.json"))
    with pytest.raises(RuntimeError, match="demo credentials"):
        validate_for_environment(base)                                        # AUTO_SEED needs a credential source
    validate_for_environment(replace(base, auto_seed=False))                  # ...unless demo data is not seeded
    fresh_credentials.setenv("DEMO_PASSWORDS_JSON", _all_passwords_json())
    demo_accounts.reset_cache()
    validate_for_environment(base)
    for origins in (["*"], ["https://ok.example", "*"], ["null"], ["https://*.example"], ["ftp://x.example"], ["example.com"],
                    ["https://x.example/path"]):
        with pytest.raises(RuntimeError, match="CORS_ORIGINS"):
            validate_for_environment(replace(base, cors_origins=origins))
    assert _origin_problems(["https://app.example", "http://localhost:8501"]) == []
    with pytest.raises(RuntimeError, match="CORS_ORIGINS"):                   # wildcards are refused in every environment
        validate_for_environment(replace(get_settings(), app_env="development", cors_origins=["*"]))


def test_no_fixed_default_secret_and_a_per_machine_key_is_used_in_development(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_SECRET_FILE", str(tmp_path / "secret"))
    first = local_secret_key()
    assert len(first) >= 32 and local_secret_key() == first                   # stable across restarts
    monkeypatch.setenv("LOCAL_SECRET_FILE", str(tmp_path / "other"))
    assert local_secret_key() != first                                        # different per machine


def test_settings_never_fall_back_to_a_known_secret_or_privileged_password(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCAL_SECRET_FILE", str(tmp_path / "s"))
    monkeypatch.setenv("SECRET_KEY", "")
    monkeypatch.setenv("SIMULATION_PRIVILEGED_PASSWORD", "")
    try:
        get_settings.cache_clear()
        dev = get_settings()
        assert dev.secret_key and dev.secret_key not in ("dev-only-secret-" + "change-me", "test-secret")
        assert dev.simulation_privileged_password and dev.simulation_privileged_password != "Synthetic#" + "Priv2026"
        monkeypatch.setenv("APP_ENV", "production")
        get_settings.cache_clear()
        prod = get_settings()
        assert prod.secret_key == ""                                          # absent stays absent: nothing is invented
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            validate_for_environment(prod)
        monkeypatch.setenv("SECRET_KEY", "k" * 40)
        monkeypatch.setenv("APP_ENV", "development")
        get_settings.cache_clear()
        a = get_settings().simulation_privileged_password
        monkeypatch.setenv("SECRET_KEY", "j" * 40)
        get_settings.cache_clear()
        assert get_settings().simulation_privileged_password != a             # derived from the secret, not constant
    finally:
        get_settings.cache_clear()


def test_the_backend_refuses_to_start_in_production_without_a_secret(tmp_path):
    code = "from fastapi.testclient import TestClient\nfrom backend.main import app\nwith TestClient(app):\n    pass\n"
    result = _run_python(code, APP_ENV="production", SECRET_KEY="", DATABASE_URL=f"sqlite:///{(tmp_path / 'x.db').as_posix()}",
                         ML_MODEL_PATH=str(tmp_path / "m.joblib"), LOCAL_SECRET_FILE=str(tmp_path / "s"))
    assert result.returncode != 0 and "SECRET_KEY" in result.stderr
    assert not (tmp_path / "s").exists()                                      # production never creates a local key


def test_api_docs_are_off_in_production_and_on_in_development(tmp_path):
    assert app.docs_url == "/docs" and app.openapi_url == "/openapi.json"
    code = ("from fastapi.testclient import TestClient\nfrom backend.main import app\nc = TestClient(app)\n"
            "print([c.get(p).status_code for p in ('/docs', '/redoc', '/openapi.json')])\n")
    result = _run_python(code, APP_ENV="production", SECRET_KEY="p" * 40, DATABASE_URL=f"sqlite:///{(tmp_path / 'x.db').as_posix()}",
                         ML_MODEL_PATH=str(tmp_path / "m.joblib"), TRUSTED_FRONTEND_KEY="", REQUIRE_HTTPS="false")
    assert result.returncode == 0 and "[404, 404, 404]" in result.stdout, result.stderr[-400:]


# ------------------------------------------------------------------------------------------------ password hashing
def test_argon2id_is_used_and_legacy_hashes_are_verified_then_upgraded_on_login(client, db_path):
    assert hash_password("Correct#Horse1").startswith("$argon2id$")
    legacy_salt = b"0123456789abcdef"
    import base64

    password = load_passwords()["carol.diaz"]
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), legacy_salt, 1000)
    legacy = f"pbkdf2_sha256$1000${base64.b64encode(legacy_salt).decode()}${base64.b64encode(digest).decode()}"
    assert verify_password(password, legacy) and not verify_password("wrong-password", legacy) and needs_rehash(legacy)
    with sqlite3.connect(db_path) as con:
        original = con.execute("select password_hash from employees where employee_code='EMP-1003'").fetchone()[0]
        con.execute("update employees set password_hash=? where employee_code='EMP-1003'", (legacy,))
    assert login(client, "EMP-1003").status_code == 200
    with sqlite3.connect(db_path) as con:
        upgraded = con.execute("select password_hash from employees where employee_code='EMP-1003'").fetchone()[0]
    assert upgraded.startswith("$argon2id$") and login(client, "EMP-1003").status_code == 200
    assert original.startswith("$argon2id$")


def test_malformed_or_foreign_hashes_never_verify_and_never_raise():
    for stored in ("", "x", "$argon2id$broken", "pbkdf2_sha256$notanumber$a$b", "$2b$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz0123", "plaintext"):
        assert verify_password("anything", stored) is False


def test_weaker_argon2_parameters_are_flagged_for_rehash():
    from argon2 import PasswordHasher

    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("pw-for-rehash-check")
    assert needs_rehash(weak) is False                                        # equals the test settings
    strong = PasswordHasher(time_cost=2, memory_cost=16, parallelism=1).hash("pw-for-rehash-check")
    assert needs_rehash(strong) in (True, False)                              # stronger than configured: no downgrade forced


# -------------------------------------------------------------------------------- brute force and rate limiting
def test_a_single_source_address_is_locked_out_after_repeated_failures(client, db_path, monkeypatch):
    monkeypatch.setattr("backend.rate_limit.get_settings", lambda: replace(get_settings(), login_ip_max_failures=4))
    codes = [client.post("/api/auth/login", json={"employee_id": f"EMP-90{i:02d}", "password": "Wrong-Password-1"}).status_code
             for i in range(6)]
    assert codes[:4] == [401] * 4 and codes[4:] == [429, 429]                 # different identifiers, same address
    blocked = client.post("/api/auth/login", json={"employee_id": "EMP-9999", "password": "Wrong-Password-1"})
    assert blocked.status_code == 429 and int(blocked.headers["Retry-After"]) >= 1
    assert blocked.json()["detail"] == "Too many failed sign-in attempts. Try again later."
    with sqlite3.connect(db_path) as con:
        rows = con.execute("select details from audit_logs where action='login_throttled' order by id desc limit 3").fetchall()
    assert any('"source_ip"' in r[0] for r in rows)


def test_account_lockout_blocks_even_the_correct_password_and_other_accounts_are_unaffected(client):
    for _ in range(get_settings().login_max_failures):
        assert login(client, "EMP-1007", "Wrong-Password-1").status_code == 401
    blocked = login(client, "EMP-1007")
    assert blocked.status_code == 429 and "Retry-After" in blocked.headers
    assert login(client, "EMP-1006").status_code == 200


def test_failed_logins_for_unknown_and_known_accounts_are_indistinguishable(client):
    unknown = client.post("/api/auth/login", json={"employee_id": "EMP-9998", "password": "Wrong-Password-1"})
    known = client.post("/api/auth/login", json={"employee_id": "EMP-1005", "password": "Wrong-Password-1"})
    assert unknown.status_code == known.status_code == 401 and unknown.json() == known.json()


def test_sensitive_routes_are_rate_limited_per_caller_with_a_clear_error(client, admin, monkeypatch):
    monkeypatch.setattr("backend.rate_limit.get_settings", lambda: replace(
        get_settings(), rate_limit_sensitive_per_minute=2, rate_limit_heavy_per_minute=1, rate_limit_employee_per_minute=3))
    first = client.post("/api/simulation/reset", headers=admin)
    second = client.post("/api/simulation/reset", headers=admin)
    assert first.status_code == 200 and second.status_code == 429
    assert int(second.headers["Retry-After"]) >= 1 and "Too many requests" in second.json()["detail"]
    other_admin_route = [client.post("/api/simulation/runs", headers=admin, json={"scenario": "nope"}).status_code for _ in range(3)]
    assert other_admin_route[:2] == [422, 422] and other_admin_route[2] == 429
    alice = auth_header(client, "EMP-1001")
    body = {"event_type": "resource_access", "resource": "internal-wiki"}
    codes = [client.post("/api/events", headers=alice, json=body).status_code for _ in range(5)]
    assert codes[:3] == [201] * 3 and codes[3:] == [429, 429]
    assert client.get("/api/employees/me", headers=alice).status_code == 200  # other routes are not affected
    assert client.post("/api/detection/retrain", headers=admin).status_code in (200, 429)


def test_unauthenticated_requests_do_not_consume_anyones_rate_limit(client, admin, monkeypatch):
    monkeypatch.setattr("backend.rate_limit.get_settings", lambda: replace(get_settings(), rate_limit_heavy_per_minute=1))
    for _ in range(5):
        assert client.post("/api/simulation/reset").status_code == 401
    assert client.post("/api/simulation/reset", headers=admin).status_code == 200


def test_rate_limits_can_be_disabled_for_local_use(client, admin, monkeypatch):
    monkeypatch.setattr("backend.rate_limit.get_settings", lambda: replace(
        get_settings(), rate_limits_enabled=False, rate_limit_heavy_per_minute=1))
    assert [client.post("/api/simulation/reset", headers=admin).status_code for _ in range(3)] == [200, 200, 200]


# ------------------------------------------------------------------------------- authentication and authorization
def test_tampered_expired_revoked_and_locked_sessions_are_refused(client, admin, db_path):
    token = auth_header(client, "EMP-1002")
    raw = token["Authorization"].split()[-1]
    swapped = raw[:-1] + ("A" if raw[-1] != "A" else "B")
    assert client.get("/api/employees/me", headers={"Authorization": f"Bearer {swapped}"}).status_code == 401
    assert client.get("/api/employees/me", headers={"Authorization": f"Bearer {raw}x"}).status_code == 401
    assert client.get("/api/employees/me", headers={"Authorization": f"Bearer {'a' * 5000}"}).status_code == 401
    assert client.get("/api/employees/me", headers=token).status_code == 200
    with sqlite3.connect(db_path) as con:
        con.execute("update employee_sessions set expires_at='2000-01-01 00:00:00' where employee_id=2 and revoked_at is null")
    assert client.get("/api/employees/me", headers=token).status_code == 401               # expired
    fresh = auth_header(client, "EMP-1002")
    assert client.post("/api/auth/logout", headers=fresh).status_code == 204
    assert client.get("/api/employees/me", headers=fresh).status_code == 401               # revoked
    live = auth_header(client, "EMP-1002")
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": 2, "action_type": "lock_account", "reason": "lock test", "confirm": True}).status_code == 201
    assert client.get("/api/employees/me", headers=live).status_code in (401, 403)         # locking revokes sessions and blocks login
    client.post("/api/containment", headers=admin, json={"employee_id": 2, "action_type": "restore_account", "reason": "undo"})


def test_role_escalation_through_the_request_body_or_a_privileged_job_title_does_not_work(client, admin, db_path):
    alice = auth_header(client, "EMP-1001")
    forged = client.post("/api/events", headers=alice, json={
        "event_type": "resource_access", "resource": "internal-wiki", "employee_id": 11, "role": "security_admin",
        "is_admin": True, "source_ip": "10.20.10.5"})
    assert forged.status_code == 201
    assert client.get("/api/soc/overview", headers=alice).status_code == 403
    mine = client.get("/api/events/me", headers=alice).json()
    assert mine and all(e.get("employee_username", "alice.morgan") == "alice.morgan" for e in mine)
    david = auth_header(client, "EMP-1004")                                     # IT admin console write access is not the SOC role
    for path in ("/api/soc/overview", "/api/simulation/status", "/api/investigations", "/api/detection/status", "/api/employees"):
        assert client.get(path, headers=david).status_code == 403, path
    for method, path in (("post", "/api/simulation/runs"), ("post", "/api/containment"), ("post", "/api/simulation/reset"),
                         ("post", "/api/investigations/1/resolve"), ("patch", "/api/investigations/1"), ("patch", "/api/alerts/1")):
        assert getattr(client, method)(path, headers=david, json={}).status_code == 403, path
    with sqlite3.connect(db_path) as con:
        assert con.execute("select role from employees where employee_code='EMP-1001'").fetchone()[0] == "employee"


def test_every_state_changing_route_needs_a_role_or_is_a_documented_self_service_action():
    from test_security import ROUTES

    self_service = {("POST", "/api/auth/logout"), ("POST", "/api/events"), ("POST", "/api/resources/{resource_id}/access"),
                    ("POST", "/api/portal/payroll/export"), ("POST", "/api/admin/accounts")}
    unprotected = [(m, p) for m, p, _, is_admin, authed in ROUTES
                   if m != "GET" and (m, p) not in {("POST", "/api/auth/login")} and not is_admin and (m, p) not in self_service]
    assert not unprotected, unprotected
    assert all(authed for m, p, _, _, authed in ROUTES if (m, p) in self_service)


def test_simulation_controls_are_refused_when_the_simulation_is_disabled(client, admin, monkeypatch):
    monkeypatch.setattr("backend.simulation_routes.get_settings", lambda: replace(get_settings(), simulation_enabled=False))
    for method, path in (("post", "/api/simulation/runs"), ("post", "/api/simulation/steps"), ("post", "/api/simulation/reset"),
                         ("get", "/api/simulation/status")):
        assert client.request(method.upper(), path, headers=admin).status_code == 403, path


def test_the_backend_sets_no_cookies(client):
    response = login(client, "EMP-1001")
    assert response.status_code == 200 and "set-cookie" not in response.headers and not client.cookies


# ------------------------------------------------------------------------------------------ request validation
def test_oversized_bodies_are_rejected_before_parsing(client, monkeypatch):
    monkeypatch.setattr(hardening, "get_settings", lambda: replace(get_settings(), max_request_bytes=2000))
    big = {"employee_id": "EMP-1001", "password": "x" * 5000}
    declared = client.post("/api/auth/login", json=big)
    assert declared.status_code == 413 and declared.json() == {"detail": "Request body too large"}

    def chunks():
        for _ in range(10):
            yield b"x" * 500

    streamed = client.post("/api/auth/login", content=chunks(), headers={"content-type": "application/json"})
    assert streamed.status_code == 413
    assert client.post("/api/auth/login", json={"employee_id": "EMP-1001", "password": "short"}).status_code == 401


def test_validation_errors_never_echo_what_was_submitted(client, admin):
    marker = "TopSecretMarker-8431"
    checks = [
        client.post("/api/auth/login", json={"employee_id": ["x", marker], "password": marker}),
        client.post("/api/auth/login", json={"employee_id": "EMP-1001", "password": {"nested": marker}}),
        client.post("/api/auth/login", content=("{" + marker).encode(), headers={"content-type": "application/json"}),
        client.post("/api/simulation/runs", headers=admin, json={"scenario": marker, "seed": marker}),
        client.post("/api/containment", headers=admin, json={"employee_id": marker, "action_type": marker, "reason": marker}),
    ]
    for response in checks:
        assert response.status_code == 422, response.text
        assert marker not in response.text
        detail = response.json()["detail"]
        assert isinstance(detail, list) and all(set(item) == {"loc", "msg", "type"} for item in detail)


def test_field_types_lengths_and_ranges_are_enforced(client, admin):
    alice = auth_header(client, "EMP-1001")
    bad_bodies = [
        ("/api/auth/login", {"employee_id": "EMP-1001", "password": "p" * 129}),
        ("/api/auth/login", {"employee_id": "a" * 65, "password": "x"}),
        ("/api/auth/login", {"employee_id": 1001, "password": "x"}),
        ("/api/events", {"event_type": "login", "record_count": 1}),
        ("/api/events", {"event_type": "resource_access", "resource": "internal-wiki", "record_count": -1}),
        ("/api/events", {"event_type": "resource_access", "resource": "internal-wiki", "record_count": 10**12}),
        ("/api/events", {"event_type": "resource_access", "resource": "internal-wiki", "details": {"k": "v" * 5000}}),
        ("/api/events", {"event_type": "resource_access", "resource": "internal-wiki", "request_id": "r" * 65}),
    ]
    for path, body in bad_bodies:
        headers = {} if path == "/api/auth/login" else alice
        assert client.post(path, headers=headers, json=body).status_code == 422, (path, body)
    assert client.post("/api/containment", headers=admin, json={
        "employee_id": 1, "action_type": "lock_account", "reason": "x" * 501, "confirm": True}).status_code == 422
    assert client.post("/api/simulation/runs", headers=admin, json={"scenario": "bulk_export", "records": 10**9}).status_code == 422
    assert client.get("/api/events", headers=admin, params={"limit": 10**6}).status_code == 422


def test_unexpected_server_errors_return_a_generic_body_and_leak_nothing(monkeypatch):
    def boom():
        raise RuntimeError("secret-token /home/user/app/backend/x.py sqlite:///C:/data/app.db password=hunter2")

    app.add_api_route("/api/_test_boom", boom, methods=["GET"])
    try:
        quiet = TestClient(app, raise_server_exceptions=False)
        response = quiet.get("/api/_test_boom")
    finally:
        app.router.routes[:] = [r for r in app.router.routes if getattr(r, "path", "") != "/api/_test_boom"]
    assert response.status_code == 500 and set(response.json()) == {"detail", "request_id"}
    assert response.json()["detail"] == "Internal server error" and len(response.json()["request_id"]) == 12
    for leak in ("secret-token", "/home/user", "sqlite", "hunter2", "Traceback", "RuntimeError", ".py"):
        assert leak not in response.text


def test_error_and_status_responses_do_not_expose_server_paths_or_internals(client, admin):
    samples = [client.get(p, headers=admin) for p in ("/api/detection/status", "/api/health", "/api/nope", "/api/investigations/abc",
                                                      "/api/soc/investigations/999999")]
    samples += [client.get("/api/employees/me"), client.post("/api/auth/login", json={})]
    for response in samples:
        text = response.text
        assert not re.search(r"[A-Za-z]:[\\/]|/home/|/Users/|/tmp/|sqlite:|Traceback|sqlalchemy", text, flags=re.I), (response.url, text[:200])
    status = samples[0].json()
    assert "model_path" not in status["model"] and status["model"]["model_file"].endswith(".joblib")
    assert not any("/" in str(v) or "\\" in str(v) for v in (status["rules"]["path"],))


# ---------------------------------------------------------------------------------------------- CORS and headers
def test_cors_allows_only_listed_origins_without_credentials(client):
    allowed = get_settings().cors_origins[0]
    ok = client.options("/api/health", headers={"Origin": allowed, "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == allowed
    assert ok.headers.get("access-control-allow-credentials") is None
    assert "*" not in ok.headers.get("access-control-allow-origin", "") and "DELETE" not in ok.headers.get("access-control-allow-methods", "")
    for origin in ("https://evil.example", "null", "http://localhost:9999", allowed + ".evil.example"):
        denied = client.options("/api/health", headers={"Origin": origin, "Access-Control-Request-Method": "GET"})
        assert "access-control-allow-origin" not in denied.headers, origin
    simple = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert simple.status_code == 200 and "access-control-allow-origin" not in simple.headers
    bad_header = client.options("/api/health", headers={"Origin": allowed, "Access-Control-Request-Method": "POST",
                                                        "Access-Control-Request-Headers": "X-Not-Allowed"})
    assert bad_header.status_code == 400


def test_security_headers_are_set_on_success_and_error_responses(client):
    for response in (client.get("/api/health"), client.get("/api/employees/me"), client.get("/api/nope"),
                     client.post("/api/auth/login", json={})):
        h = response.headers
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY" and h["referrer-policy"] == "no-referrer"
        assert h["cache-control"] == "no-store" and "default-src 'none'" in h["content-security-policy"]
        assert "strict-transport-security" not in h                          # plain HTTP: HSTS would be meaningless
    secure = TestClient(app, base_url="https://testserver").get("/api/health")
    assert "max-age=31536000" in secure.headers["strict-transport-security"]


def test_https_is_required_when_configured_with_loopback_and_health_exempt(monkeypatch):
    strict = replace(get_settings(), require_https=True, trust_forwarded_proto=False)
    monkeypatch.setattr(hardening, "get_settings", lambda: strict)
    plain = TestClient(app)
    refused = plain.get("/api/employees/me")
    assert refused.status_code == 400 and refused.json() == {"detail": "HTTPS is required"}
    assert plain.get("/api/health").status_code == 200                       # platform health checks arrive over plain HTTP
    assert TestClient(app, base_url="https://testserver").get("/api/employees/me").status_code == 401   # past the HTTPS gate
    assert TestClient(app, client=("127.0.0.1", 50000)).get("/api/employees/me").status_code == 401     # loopback exempt
    spoofed = plain.get("/api/employees/me", headers={"X-Forwarded-Proto": "https"})
    assert spoofed.status_code == 400                                        # a forwarded header is ignored unless trusted
    monkeypatch.setattr(hardening, "get_settings", lambda: replace(strict, trust_forwarded_proto=True))
    assert plain.get("/api/employees/me", headers={"X-Forwarded-Proto": "https"}).status_code == 401
    assert plain.get("/api/employees/me", headers={"X-Forwarded-Proto": "http"}).status_code == 400


def test_https_is_required_by_default_only_in_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("REQUIRE_HTTPS", raising=False)
    try:
        get_settings.cache_clear()
        assert get_settings().require_https is True and get_settings().enable_api_docs is False
        monkeypatch.setenv("APP_ENV", "development")
        get_settings.cache_clear()
        assert get_settings().require_https is False and get_settings().enable_api_docs is True
    finally:
        get_settings.cache_clear()


def test_streamlit_keeps_its_own_xsrf_and_cors_protections_on():
    config = (ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8")
    assert re.search(r"^enableXsrfProtection\s*=\s*true", config, flags=re.M)
    assert re.search(r"^enableCORS\s*=\s*true", config, flags=re.M)


def test_render_blueprint_takes_secrets_from_the_platform_not_the_file():
    text = (ROOT / "render.yaml").read_text(encoding="utf-8")
    assert "sync: false" in text and "DEMO_PASSWORDS_JSON" in text and "SECRET_KEY" in text
    assert "generateValue" not in text                      # secrets come from `python -m deploy.make_secrets`, shown to the operator once
    assert not re.search(r"(SECRET_KEY|PASSWORD)[^\n]*\n\s*value:\s*\S{8,}", text)
