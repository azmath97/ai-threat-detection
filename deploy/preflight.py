"""Start-up checks and environment derivation for the single-container deployment.

`problems(env)` returns every reason the deployment must not start (names of settings only, never their values). The supervisor
(deploy/start.py) refuses to start unless it returns nothing. `child_environment(env)` builds the environment the backend and the
three Streamlit apps run with, so that nothing in a production path depends on a localhost default.

Two modes, chosen with DEPLOY_MODE:

* persistent (default): needs PostgreSQL through DATABASE_URL. Seeds the synthetic demo data only when the database is empty.
* demo: refuses DATABASE_URL altogether and uses its own throw-away SQLite file that is deleted and re-seeded at every start, so
  demo data can never mix with persistent records. Nothing survives a restart, by design.
"""
import json
import os
import re
import secrets
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path

PUBLIC_URL_PATTERN = re.compile(r"^https://[A-Za-z0-9.-]+(:\d{1,5})?$")
LOCAL_URL_PATTERN = re.compile(r"^http://(localhost|127\.0\.0\.1)(:\d{1,5})?$")
MODES = ("persistent", "demo")
PLACEHOLDERS = ("change-me", "changeme", "dev-only", "secret", "test-secret", "password")
INTERNAL = {"API_PORT": "8000", "PORTAL_PORT": "8501", "SOC_PORT": "8503"}


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def deploy_mode(env: Mapping[str, str]) -> str:
    return (env.get("DEPLOY_MODE") or "persistent").strip().lower()


def public_url(env: Mapping[str, str]) -> str:
    """PUBLIC_URL, or the URL the host assigns (Render sets RENDER_EXTERNAL_URL), without a trailing slash."""
    return (env.get("PUBLIC_URL") or env.get("RENDER_EXTERNAL_URL") or "").strip().rstrip("/")


def demo_database_url(env: Mapping[str, str]) -> str:
    folder = Path(env.get("DEMO_DB_DIR") or Path(tempfile.gettempdir()) / "westbridge-demo")
    return f"sqlite:///{(folder / 'demo.db').as_posix()}"


@contextmanager
def _patched_environ(values: Mapping[str, str]):
    saved = {k: os.environ.get(k) for k in values}
    os.environ.update({k: v for k, v in values.items() if v is not None})
    try:
        yield
    finally:
        for key, old in saved.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


def _demo_credentials_problem(env: Mapping[str, str]) -> str | None:
    """DEMO_PASSWORDS_JSON must be a JSON object that gives every demo account a strong, unique password."""
    from data import demo_accounts

    raw = env.get("DEMO_PASSWORDS_JSON", "")
    if not raw:
        return "DEMO_PASSWORDS_JSON is not set (a JSON object of username -> password for every demo account; run python -m deploy.make_secrets)"
    try:
        json.loads(raw)
    except ValueError:
        return "DEMO_PASSWORDS_JSON is not valid JSON"
    with _patched_environ({"DEMO_PASSWORDS_JSON": raw, "APP_ENV": "production",
                           "DEMO_CREDENTIALS_FILE": str(Path(tempfile.gettempdir()) / "westbridge-no-such-credentials.json")}):
        demo_accounts.reset_cache()
        try:
            demo_accounts.load_passwords(create=False)
        except demo_accounts.CredentialsMissing as exc:
            return f"DEMO_PASSWORDS_JSON is not usable: {exc}"
        finally:
            demo_accounts.reset_cache()
    return None


def problems(env: Mapping[str, str]) -> list[str]:
    found: list[str] = []
    mode = deploy_mode(env)
    if mode not in MODES:
        found.append(f"DEPLOY_MODE must be one of: {', '.join(MODES)}")

    if mode == "persistent":
        url = env.get("DATABASE_URL", "")
        if not url:
            found.append("DATABASE_URL is not set (persistent mode needs a PostgreSQL database; the container's own disk is not durable)")
        elif not url.startswith(("postgres://", "postgresql://", "postgresql+psycopg://")):
            found.append("DATABASE_URL must be a PostgreSQL URL in persistent mode (SQLite would be lost on every restart)")
    elif mode == "demo" and env.get("DATABASE_URL"):
        found.append("DATABASE_URL is set but DEPLOY_MODE=demo: demo mode uses its own throw-away database so demo data cannot mix "
                     "with persistent records. Unset DATABASE_URL, or use DEPLOY_MODE=persistent")

    secret = env.get("SECRET_KEY", "")
    if len(secret) < 32 or any(secret.lower().startswith(p) for p in PLACEHOLDERS):
        found.append("SECRET_KEY must be a random value of at least 32 characters (python -m deploy.make_secrets)")

    url = public_url(env)
    if not url:
        found.append("PUBLIC_URL is not set (the https:// address users will open; Render supplies RENDER_EXTERNAL_URL automatically)")
    elif not (PUBLIC_URL_PATTERN.match(url) or LOCAL_URL_PATTERN.match(url)):
        found.append("PUBLIC_URL must look like https://your-host (no path, no wildcard); plain http is accepted only for localhost")

    if not _flag(env.get("ALLOW_OPEN_ADMIN_UI")):
        if len(env.get("ADMIN_UI_USER", "")) < 3:
            found.append("ADMIN_UI_USER is not set             (the user name of the gate in front of the SOC dashboard)")
        if len(env.get("ADMIN_UI_PASSWORD", "")) < 16:
                        found.append("ADMIN_UI_PASSWORD must be at least 16 characters (the gate in front of the SOC dashboard)")

    if _flag(env.get("AUTO_SEED", "true")):
        problem = _demo_credentials_problem(env)
        if problem:
            found.append(problem)
    return found


def child_environment(env: Mapping[str, str]) -> dict[str, str]:
    """The environment of the backend and Streamlit processes. Assumes `problems(env)` returned nothing."""
    child = dict(env)
    url = public_url(env)
    mode = deploy_mode(env)
    for key, default in INTERNAL.items():
        child.setdefault(key, default)
    child.update(
        APP_ENV="production", DEPLOY_MODE=mode, PUBLIC_URL=url,
        API_HOST="127.0.0.1", API_BASE_URL=f"http://127.0.0.1:{child['API_PORT']}",
        CORS_ORIGINS=url, ENABLE_API_DOCS=env.get("ENABLE_API_DOCS", "false"),
        MAP_LOOPBACK_TO_WORKSTATION="true",           # every client of the backend is a Streamlit process on loopback
        REQUIRE_HTTPS="true",                         # loopback and /api/health are exempt; the backend is never public
        AUTO_SEED=env.get("AUTO_SEED", "true"), ML_AUTO_TRAIN=env.get("ML_AUTO_TRAIN", "true"),
        FORCE_HTTPS="true" if url.startswith("https://") else "false",
        STREAMLIT_SERVER_CORS_ALLOWED_ORIGINS=url,    # the websocket origin check admits only the deployed address
        PYTHONUNBUFFERED="1",
    )
    # The dashboards and the backend share a key generated for this start: it lets the backend believe the end user's address
    # that the gateway measured (X-Client-IP). An operator-supplied key is kept. Render sets RENDER=true and puts a proxy in front,
    # which is the only reason the gateway may read X-Forwarded-For; anywhere else set TRUST_FORWARDED_FOR yourself.
    child.setdefault("TRUSTED_FRONTEND_KEY", secrets.token_urlsafe(32))
    child.setdefault("TRUST_FORWARDED_FOR", "true" if env.get("RENDER") else "false")
    if mode == "demo":
        child["DATABASE_URL"] = demo_database_url(env)
        child["ALLOW_SQLITE_IN_PRODUCTION"] = "true"  # explicit: the demo database is meant to be disposable
    return child
