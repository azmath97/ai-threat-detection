# Deploying the platform

This is an **educational** insider-threat and account-defence demo with synthetic data. It is not production
banking security. Its enforcement (account locks, address blocks, session revocation) acts only inside this application, and the
investigation containment buttons only change its own records; nothing here touches a firewall, a network or a real system. Deploying it publishes that demo; it does
not make it a bank-grade service.

> **Status: prepared and rehearsed locally, not deployed.** No Render (or other) account was available while this was written,
> so no public URL exists and none is claimed. The Dockerfile and `render.yaml` have not been built or run by anyone.
> Section 6 lists exactly what was and was not verified.

## 1. Why one container

The application is three processes: the FastAPI backend and two Streamlit apps (employee portal and SOC dashboard). Streamlit Community Cloud runs a single Streamlit file and Vercel-style function hosts cannot hold the long-lived
backend or Streamlit's websockets, so neither fits unchanged. Render runs a Docker service with one public port, so one
container runs everything and a small gateway (`deploy/gateway.py`) is the only thing exposed:

```text
internet -> Render (TLS) -> gateway :$PORT --+-- /          employee portal   127.0.0.1:8501
                                             +-- /soc/      SOC dashboard     127.0.0.1:8503  (admin login)
                                             +-- /healthz   probes all three
                                             +-- /api, /docs, /redoc, /openapi.json -> 404 (never public)
                              backend (FastAPI) 127.0.0.1:8000, reached only by the two apps -> PostgreSQL
```

- **The API is private on purpose.** The dashboards call it from inside the container, so there is no browser-to-API CORS
  path and `CORS_ORIGINS` is just the public URL. Exposing it would also let outside callers inherit the "registered
  workstation" attribution that loopback clients get, which would break unfamiliar-address detection.
- **Admin pages are gated twice**: the gateway asks for a browser login (HTTP Basic, `ADMIN_UI_USER` / `ADMIN_UI_PASSWORD`)
  before `/soc/`, and the backend then still enforces role-based access on every call. Failed gate logins are
  limited to 10 per 5 minutes per client.
- **Nothing is public with default credentials.** There are none: the container refuses to start unless every secret below is
  set, and the demo-account passwords are random values you generate.

## 2. Modes

| `DEPLOY_MODE` | Data | Use |
|---|---|---|
| `persistent` (default) | Your PostgreSQL database from `DATABASE_URL`. Survives restarts and redeploys. | A shared demo whose investigations you want to keep. |
| `demo` | A throw-away SQLite file in the container's temp directory, deleted and re-seeded at every start. **Refuses** `DATABASE_URL`. | A disposable public showcase. Demo data can never mix with persistent records. |

The container's own filesystem is ephemeral on Render, which is why persistent mode requires PostgreSQL and `persistent` with
SQLite is rejected at startup.

## 3. Settings

All are set in the host's environment settings (Render: service -> Environment). Never commit them.

| Variable | Required | Notes |
|---|---|---|
| `SECRET_KEY` | yes | 32+ random characters. Signs sessions and the gate cookie. |
| `DEMO_PASSWORDS_JSON` | yes | JSON object `{"username": "password", ...}` for all 11 demo accounts. |
| `ADMIN_UI_USER`, `ADMIN_UI_PASSWORD` | yes | Gate login for `/soc/` (3+ / 16+ characters). Waived only by `ALLOW_OPEN_ADMIN_UI=true`. |
| `DATABASE_URL` | persistent mode | `postgresql://...` (`postgres://` is accepted). Forbidden in demo mode. |
| `PUBLIC_URL` | unless on Render | `https://...` address of the service. Render supplies `RENDER_EXTERNAL_URL`. |
| `DEPLOY_MODE` | no | `persistent` (default) or `demo`. |
| `PORT` | no | Set by the host. Default 8080. |

Startup validation (`deploy/preflight.py`) lists every problem **by setting name only, never by value**, then exits with code
2 before any process starts. Logs contain no secrets; the logging of upstream request URLs is turned down for that reason.

`python -m deploy.make_secrets` generates `SECRET_KEY`, `DEMO_PASSWORDS_JSON`, `ADMIN_UI_USER` and `ADMIN_UI_PASSWORD`. It prints
to your terminal only and writes nothing to disk. Keep the output in a password manager: the demo sign-in passwords exist only
there and in the host's settings.

## 4. Step by step (Render)

These need your own account, so they are manual:

1. **Create a Render account** and connect GitHub (`azmath97/ai-threat-detection`).
2. **Create a PostgreSQL database** (Render -> New -> PostgreSQL) in the same region you will use for the service. Copy its
   **Internal Database URL** (for a service in the same region) or External URL.
3. On your own machine run `python -m deploy.make_secrets` and keep the output.
4. Render -> New -> **Blueprint** -> select the repository. `render.yaml` defines one Docker web service on the `1c-2g` plan.
   The four processes of the earlier layout needed roughly 0.6 GB while idle (measured on Windows, see section 6; the current three need less but were not re-measured), so the free and 512 MB plans will not
   fit. Enter the values it asks for (`DATABASE_URL`, `SECRET_KEY`, `DEMO_PASSWORDS_JSON`, `ADMIN_UI_USER`, `ADMIN_UI_PASSWORD`).
   For a disposable showcase, change `DEPLOY_MODE` to `demo` and leave `DATABASE_URL` empty.
5. Wait for the first deploy. The Docker build trains the anomaly model from the repository's seeded synthetic generator
   (about a minute); nothing has to be uploaded. Render's health check is `/healthz`.
6. Open the service URL and run the checks below.

To move an existing local demo database into PostgreSQL see "Database" in the README (`python -m backend.db_tools copy`).

## 5. Required checks after deploying

Run the public checks from any machine:

```bash
python -m deploy.verify --url https://YOUR-SERVICE.onrender.com --gate-user "$ADMIN_UI_USER" --gate-password "$ADMIN_UI_PASSWORD"
```

They check: the site loads, `/healthz` is green, `/api` and `/docs` are 404, security headers and HSTS, plain HTTP redirects to
HTTPS, the admin pages refuse a missing or wrong gate login, the Streamlit websocket handshake works through the gateway, and
none of your secrets appear in any page or header.

The behaviour checks need the private API, so run them in the Render **Shell** of the service (they sign in, ingest an event
with a retried idempotency key, confirm one stored event, compare dashboard totals, confirm refused requests are recorded, hold,
approve and use a bulk export once, and, when `--frontend-key` is given, lock an account with five failed sign-ins and unlock it).
Those checks send real requests, so what they cause stays in the audit trail (one event, one approved 12,000-record export request
for `EMP-1001`, and five failed sign-ins for `EMP-1010`); prefer a `demo` deployment for them. The lock check needs the shared
`TRUSTED_FRONTEND_KEY`: set it yourself as a service secret (a random 24+ character value; the container keeps a key you supply and
otherwise generates one at each start) and pass it as `VERIFY_FRONTEND_KEY`. Without it that one check prints SKIP.

```bash
VERIFY_EMPLOYEE_PASSWORD=... VERIFY_ADMIN_PASSWORD=... VERIFY_FRONTEND_KEY=... \
python -m deploy.verify --api http://127.0.0.1:8000 --snapshot /tmp/snap.json
```

Persistence (persistent mode): restart the service from the Render dashboard, then in the shell:

```bash
VERIFY_ADMIN_PASSWORD=... python -m deploy.verify --api http://127.0.0.1:8000 --compare /tmp/snap.json
```

`/tmp` is wiped by a restart, so print the snapshot (`cat /tmp/snap.json`) and save it somewhere safe before restarting, then
recreate the file in the shell before running `--compare`. Every check prints PASS or FAIL with what it observed and the exit
code is non-zero on a failure.

Also do by hand once, in a browser: sign in as an employee and as a security administrator, confirm an employee cannot reach
the SOC pages, and reload a page a few times to see that the event count does not grow (a repeated identical action within
`PORTAL_REPEAT_WINDOW_SECONDS` is stored once).

## 6. What was and was not verified

**Verified on a Windows development machine** (a faithful rehearsal, not a deployment):

- The whole stack through `python -m deploy.start`, in `demo` mode and in `persistent` mode against a real embedded PostgreSQL
  16 server, with the earlier version of `deploy.verify` (which drove a scenario console that has since been removed) passing every public and
  behaviour check (25 of 25). The current verifier has been run only against a local backend process, inside `tests/test_runtime.py`
  (14 behaviour checks plus the restart comparison); it has not been re-run against the full container stack.
- A hard kill and restart of the stack on PostgreSQL, then `deploy.verify --compare` (3 of 3): same database, no lower row
  counts, the marker event still stored.
- `requirements-deploy.txt` installed in a clean virtual environment with no test dependencies; `python -m ml.train_model` then
  built the model and the stack started from it.
- Browser sign-in through the gateway; a double-clicked download stored one event and page reloads stored none.
- A scan of the stack's logs for the secret key, gate password, demo passwords and database URL found none.
- Automated tests in `tests/test_deploy.py` for startup validation, the gateway, and the deployment files.

**Not verified** (so do not rely on it until you have run section 5):

- The Docker image has never been built here (no Docker was available), and `render.yaml` has never been applied.
- Nothing has run on Render or Linux: memory under real sessions and load are unmeasured.
- No public URL exists, so TLS, HSTS and redirect behaviour on the real host are untested beyond unit tests.
- Streamlit's websocket origin check with a non-localhost public origin was tested with a simulated forwarded host, not a real one.

## 7. Limits

SQLite in `demo` mode and the single-container design are for a demonstration. Gateway rate limiting and backend rate limits are
in-process, so run exactly one instance. There is no autoscaling, backup policy or monitoring beyond `/healthz` and the logs;
use your PostgreSQL provider's backups if you keep data. The data is synthetic (CERT r4.2 benchmark data is not shipped and is
never uploaded by this deployment).
