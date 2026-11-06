# AI-Based Insider Threat Detection System

A real-time security-monitoring and response platform for a fictional financial organisation, **Westbridge Bank**. Employees use
an Employee Workspace Portal; a security team watches the same backend through a Security Operations Centre (SOC) dashboard.
The backend records every sign-in and every refused request as it happens, detects brute force, credential stuffing,
probing of other people's records, bulk exports and compromised-account behaviour, and responds automatically. It is a research
and teaching project, not a security product, and it has not been validated against real traffic.

## Scope: what is enforced and what is not

* **Detection runs on the requests this application actually receives.** Every sign-in attempt, refused request and export
  is stored, evaluated inside time windows, and turned into an incident with its evidence. The accounts, employees and
  historical activity are synthetic: there are no real credentials, personal data or banking data.
* **Enforcement is real inside this application.** A locked account cannot sign in and its sessions stop working; a blocked
  address is refused by the login code; removed permissions deny access; a bulk export is held until a security administrator
  approves it. The backend checks all of this on every request, and each action is recorded with who or what did it, when and
  why.
* **Nothing outside this application is touched.** Specifically, the project:
  * does not block real network traffic;
  * does not disable real accounts;
  * does not quarantine real devices;
  * does not send email or contact a directory, firewall or endpoint agent;
  * does not protect a real bank.

  No such integration exists or is configured. An address "block" is a refusal by this application's own code, not a firewall rule.
* **Containment actions are auditable.** Each one records the alert and/or investigation, the requested action, who
  initiated it, when, the result and the records it changed, plus an audit-log entry. The buttons say "Run containment" and
  the result "Containment completed" for that reason.
* The score thresholds are untuned starting values, and the benchmark results in this README are on historical or synthetic data.

* **One FastAPI backend and one configured database are the single source of truth** (SQLite for local development,
  PostgreSQL for anything deployed; see [Database and persistence](#database-and-persistence)). The portal, the SOC
  dashboard only call the backend; neither has its own data, scores or event system.
* **Detection is hybrid, and its numbers are labelled for what they are:** an Isolation Forest anomaly model, configurable rules and
  event correlation produce a **heuristic risk score** (0-100, hand-weighted, **not a probability**), a **risk band** (a calibrated
  threshold on that score, limited by how many independent attack stages the evidence spans), a separate **impact severity**
  (what the evidence shows was accessed or changed) and a qualitative **evidence strength**. See
  [How the scores are defined](#how-the-scores-are-defined).
* **Containment has visible effects inside the application:** disabling an account stops logins to this application, an IP
  block makes its login code refuse that address, and removing privileges deletes permission rows. It never touches a
  real network.

## Contents

1. [Architecture](#architecture)
2. [Technology stack](#technology-stack)
3. [Install and run](#install-and-run) and [deploy to the cloud](#deploying-to-the-cloud)
4. [Environment setup](#environment-setup)
5. [Database initialisation](#database-initialisation) and [database and persistence](#database-and-persistence)
6. [Demo credentials](#demo-credentials)
7. [Launching](#launching-the-application)
8. [Exercise the platform](#how-to-exercise-the-platform) and [the offline scenario lab](#the-offline-scenario-lab)
9. [How it works, end to end](#how-it-works-end-to-end)
10. [The data: what is stored and what datasets are used](#the-data)
11. [Machine learning in detail](#machine-learning-in-detail)
12. [Detection rules in detail](#detection-rules-in-detail)
13. [Baseline, correlation, scoring and data exposure](#baseline-correlation-scoring-and-data-exposure)
14. [The lab's attack stages, step by step](#the-labs-attack-stages-step-by-step)
15. [How attacks are prevented, contained and what is not prevented](#how-attacks-are-prevented-contained-and-what-is-not-prevented)
16. [Employee Portal](#employee-workspace-portal) and [SOC dashboard](#soc-dashboard)
17. [Investigation and incident response](#investigation-and-incident-response)
18. [API](#api)
19. [Project structure](#project-structure)
20. [Tests](#tests)
21. [Security notes](#security-notes-and-limitations) and [Known limitations](#known-limitations)

## Architecture

```
 Employee Portal  (Streamlit :8501) --\
                                       ---HTTP/JSON-->  FastAPI backend (:8000)  -->  SQLite (local) or PostgreSQL (DATABASE_URL)
 SOC Dashboard    (Streamlit :8503) --/                      |
                                                            +-- ml/  Isolation Forest (ml/artifacts/*.joblib)
 every action -> security event -> rules + anomaly score -> heuristic risk score -> risk band / impact / evidence strength -> alert -> investigation
```

**Event pipeline** (`backend/event_service.py`). Every employee action is turned into a `security_events` row by the
backend, then flows through the same steps for real employees and for the simulation:

1. persist the event (identity, session, IP and device come from the authenticated session, never from the client);
2. apply the configurable rules against the employee's role, permissions, 30-day baseline and session context;
3. score the behaviour with the Isolation Forest (or the heuristic fallback);
4. correlate related events (same employee, session, unfamiliar IP, or an account created by that employee);
5. compute the heuristic risk score, the risk band, the impact severity, the evidence strength, the attack stage and the data exposure;
6. when the risk band reaches **Alert** raise an alert and create/update an investigation with preserved evidence.

The dashboards only read what the backend stored. The portal never shows scores, alerts or investigations.

| Area | Files |
|---|---|
| API and auth | `backend/main.py`, `auth_service.py`, `security.py`, `portal_routes.py`, `schemas.py` |
| Database | `backend/models.py`, `database.py`, `data/seed_data.py` (9 tables plus `response_controls` and `investigation_evidence`) |
| Detection | `detection_engine.py`, `detection_rules.json`, `rules.py`, `baseline.py`, `correlation_engine.py`, `threat_engine.py`, `data_exposure.py`, `ml/` |
| Investigation and response | `investigation_service.py`, `investigation_explainer.py`, `investigation_export.py`, `investigation_routes.py`, `response_service.py`, `controls.py` |
| SOC read models | `soc_service.py`, `soc_routes.py` |
| Offline scenario lab | `lab/scenario_generator.py` (seeded plans), `simulation_runs.py`, `simulation_service.py`, `simulation_routes.py` (tests and calibration only; `LAB_MODE=true`, refused in production, not in the image) |
| Front ends | `frontend/employee_portal.py`, `soc_dashboard.py`, `soc_auth_defense.py`, `components.py`, `soc_components.py`, `theme.py`, `api_client.py` |
| Tests | `tests/` (567 tests) |

## Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, Uvicorn, Pydantic 2 |
| Database | SQLAlchemy 2 over SQLite (local development) or PostgreSQL through `psycopg` 3 (shared / deployed), with versioned schema migrations (timestamps stored in UTC, shown in `DISPLAY_TIMEZONE`) |
| Machine learning | scikit-learn `IsolationForest`, NumPy, joblib (model saved locally and reused) |
| Dashboards | Streamlit and Plotly (charts and the attack graph); custom CSS theme in `frontend/theme.py` (responsive down to phone width, no external fonts or assets) |
| Security | Argon2id password hashes (`argon2-cffi`), random session tokens stored as HMAC digests, rate limiting, strict CORS, security headers (see [Security](#security-notes-and-limitations)) |
| Tests | pytest, FastAPI TestClient, Streamlit `AppTest` |

Pandas is not imported by the project itself; it is installed because Streamlit depends on it.

## Install and run

Windows PowerShell (Python 3.12 recommended):

```powershell
git clone https://github.com/azmath97/ai-threat-detection.git
cd ai-threat-detection
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py setup         # first time only: random SECRET_KEY in .env and random demo credentials
python app.py credentials   # show the demo sign-in credentials generated for this machine
python app.py all
```

macOS / Linux:

```bash
git clone https://github.com/azmath97/ai-threat-detection.git && cd ai-threat-detection
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py setup && python app.py credentials
python app.py all
```

`python app.py setup` is the safe local procedure. It writes `.env` (from `.env.example`) with a freshly generated random
`SECRET_KEY` and creates `data/demo_credentials.local.json` with a random password for each demo account. Both files are
git-ignored and created with owner-only permissions where the platform supports it. It is safe to re-run: existing files
are kept. Skipping it also works for a quick look (the backend then creates the same files on first start), but run
`python app.py credentials` to see the passwords. **No password or secret is stored in the repository.**

That starts the backend and both dashboards:

| Service | URL |
|---|---|
| Backend API and interactive docs | http://127.0.0.1:8000 and http://127.0.0.1:8000/docs |
| Employee Workspace Portal | http://127.0.0.1:8501 |
| SOC Dashboard (administrators) | http://127.0.0.1:8503 |

On first start the backend creates and seeds the database and trains the anomaly model (a few seconds). If port 8000
is already used, set `API_PORT` first: `$env:API_PORT="8010"; python app.py all` (bash: `API_PORT=8010 python app.py all`).
The dashboards are told where the backend is automatically.

## Environment setup

Everything works with defaults and no `.env` file. To change settings, run `python app.py setup` (which writes `.env` for you)
or copy `.env.example` to `.env` yourself (`app.py` loads it):

```powershell
Copy-Item .env.example .env        # bash: cp .env.example .env
```

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./data/insider_threat.db` | the one shared database. Local development: SQLite. Deployed: `postgresql://USER:PASSWORD@HOST:5432/DBNAME` (`postgres://` is accepted too). Production refuses SQLite unless `ALLOW_SQLITE_IN_PRODUCTION=true` |
| `ALLOW_SQLITE_IN_PRODUCTION` | `false` | only for one process whose SQLite file is on a persistent volume |
| `DB_BUSY_TIMEOUT_SECONDS` | `30` | how long a writer waits for the SQLite write lock before the request fails with 503 |
| `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_TIMEOUT_SECONDS`, `DB_POOL_RECYCLE_SECONDS` | `10`, `10`, `30`, `1800` | PostgreSQL connection pool (ignored for SQLite) |
| `DASHBOARD_WINDOW_DAYS` | `30` | the SOC overview totals cover this many days (the response says so in `window_days`) |
| `MAX_PAGE_SIZE` | `500` | most rows a list endpoint returns per request (a larger `limit` is a 422) |
| `SOC_REFRESH_SECONDS`, `SOC_CACHE_SECONDS` | `3`, `25` | read by the Streamlit apps: how often a SOC session checks the change token and how long fetched panels are reused. Values below `1` and `5` are raised to those minimums |
| `PORTAL_REPEAT_WINDOW_SECONDS` | `3` | a repeated identical portal action inside this window (double click, rerun) is recorded once |
| `SECRET_KEY` | none | keys the session-token HMAC. **No default exists.** Development: if unset, a random per-machine key is created in `data/.local_secret` (git-ignored). Production: must be set (32+ random characters) by the environment or your platform's secret manager, or the backend refuses to start |
| `DEMO_PASSWORDS_JSON` | unset | production: JSON object `{"alice.morgan": "...", ...}` giving all 11 demo usernames a unique password of 12+ characters, from a secret manager. Alternative: `DEMO_CREDENTIALS_FILE` |
| `DEMO_CREDENTIALS_FILE` | `data/demo_credentials.local.json` | local credentials file (generated outside production, git-ignored) |
| `SESSION_TTL_MINUTES` | `480` | session lifetime |
| `DISPLAY_TIMEZONE` | `Asia/Kolkata` | zone used for `*_local` timestamps and "after hours" |
| `CORS_ORIGINS` | portal and SOC origins | explicit allowed origins; a wildcard, `null` or a malformed origin stops start-up; credentials are never allowed |
| `AUTO_SEED` | `true` | seed the synthetic data when the database is empty (in production this needs a demo credential source) |
| `LAB_MODE` | `false` | mounts the offline scenario lab's API (needs the `lab/` package, which the container image does not contain). The backend **refuses to start** with `LAB_MODE=true` when `APP_ENV=production`. Tests and threshold calibration turn it on |
| `SIMULATION_PRIVILEGED_PASSWORD` | derived from `SECRET_KEY` | password of the privileged account the lab creates; used only when `LAB_MODE=true` |
| `ARGON2_TIME_COST`, `ARGON2_MEMORY_KIB`, `ARGON2_PARALLELISM` | `3`, `65536`, `2` | Argon2id cost (hashes made with weaker settings are upgraded at the next login) |
| `MAP_LOOPBACK_TO_WORKSTATION` | `true` | local demo: attribute loopback connections to the employee's registered workstation IP |
| `TRUSTED_FRONTEND_KEY` | empty (off) | split hosting: shared secret (24+ characters) sent by the dashboards as `X-Frontend-Key`; requests carrying it are attributed to the employee's registered workstation IP |
| `APP_ENV` | `development` | `production` enforces the checks above, turns on `REQUIRE_HTTPS` and turns off `/docs` |
| `REQUIRE_HTTPS`, `TRUST_FORWARDED_PROTO` | on in production, off | refuse plain-HTTP requests (loopback and `/api/health` exempt); honour `X-Forwarded-Proto` from a proxy you control |
| `ENABLE_API_DOCS` | on in development | interactive `/docs`, `/redoc` and `/openapi.json` |
| `MAX_REQUEST_BYTES` | `1000000` | largest accepted request body (HTTP 413 beyond it) |
| `LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_SECONDS` | `5`, `300` | failed sign-ins per employee ID before a temporary lockout (HTTP 429) |
| `LOGIN_IP_MAX_FAILURES`, `LOGIN_IP_WINDOW_SECONDS` | `20`, `300` | failed sign-ins from one source address before it is locked out |
| `RATE_LIMITS_ENABLED`, `RATE_LIMIT_SENSITIVE_PER_MINUTE`, `RATE_LIMIT_HEAVY_PER_MINUTE`, `RATE_LIMIT_EMPLOYEE_PER_MINUTE` | `true`, `30`, `6`, `60` | per-caller, per-route limits for administrator state changes, expensive actions (reset, retrain, reload, payroll export, account creation) and employee actions (HTTP 429 with `Retry-After`) |
| `CONTAINMENT_MAX_PER_MINUTE` | `30` | containment requests one administrator may submit per minute (HTTP 429 beyond it) |
| `API_TIMEOUT_SECONDS` | `20` | how long the dashboards wait for the API (raise it for a free host that sleeps) |
| `API_HOST`, `API_PORT`, `API_BASE_URL` | `127.0.0.1`, `8000`, `http://127.0.0.1:8000` | where the backend listens and where dashboards find it |
| `CORRELATION_WINDOW_MINUTES` | `240` | correlation window |
| `BASELINE_DAYS` | `30` | how much history forms an employee's behavioural baseline |
| `BULK_RECORD_THRESHOLD` | `500` | minimum record count that counts as a "large" export |
| `THREAT_SUSPICIOUS_THRESHOLD`, `THREAT_HIGH_THRESHOLD`, `THREAT_CRITICAL_THRESHOLD` | `37`, `37`, `37` (from `backend/operating_point.json`) | risk-score thresholds of the Watch, Elevated and Alert bands. The defaults are the operating point chosen on validation runs by `python -m ml.calibrate_scoring`; setting these variables overrides it and the dashboards then say "environment override". Without an operating point file the hand-picked 25/50/80 are used and labelled "uncalibrated defaults" |
| `OPERATING_POINT_PATH`, `ML_CORROBORATION_THRESHOLD` | `backend/operating_point.json`, `0.45` | where the recorded operating point is read from, and the anomaly score from which the model counts as agreeing with the rules (used only for evidence strength) |
| `ALERT_MIN_SEVERITY` | `critical` | lowest **risk band** that raises an alert (`critical` is the Alert band; the name is kept for compatibility) |
| `ML_MODEL_PATH`, `ML_AUTO_TRAIN` | `ml/artifacts/isolation_forest.joblib`, `true` | model file and train-on-first-start |

Rule severities, scoring weights and parameters live in `backend/detection_rules.json` (reload with
`POST /api/detection/reload`, no restart needed).

## Database initialisation

Nothing to run manually: on start-up the backend creates or upgrades the schema (see [migrations](#schema-versions-and-migrations))
and seeds the data on first start (`AUTO_SEED=true`). To rebuild from scratch:

```powershell
python -m data.seed_data --reset     # drops and re-creates the demo database
python -m ml.train_model --export    # optional: retrain the model; --export also writes ml/artifacts/*.csv
```

Data persists across restarts (SQLite file `data/insider_threat.db`, git-ignored, unless `DATABASE_URL` says otherwise).

## Database and persistence

**One store.** The backend is the only process that opens the database. The two Streamlit apps never import SQLAlchemy,
SQLite or the models (a test parses their source to prove it) and keep no business data of their own: everything they show
is fetched from `/api/*`, and what they hold in `st.session_state` is the sign-in token, filters and a short-lived copy of
what the backend returned. So the employee portal and the SOC dashboard always read the same rows,
and two dashboard sessions see the same figures.

### SQLite (local development) and its limits

The default. The backend opens it in WAL mode with `foreign_keys=ON`, `synchronous=NORMAL` and a busy timeout
(`DB_BUSY_TIMEOUT_SECONDS`), so readers and the one writer overlap and writers queue instead of failing. It is **not** a
production-scale database:

* one writer at a time, on one host, and one backend process (several processes share the file but not the in-memory state
  below); never put the file on a network share;
* a request that cannot get the write lock within the busy timeout gets **HTTP 503 with `Retry-After`** and a generic body;
* `synchronous=NORMAL` survives an application crash or a forced kill of the backend (tested), but the last few transactions can
  be lost if the whole machine loses power;
* no encryption at rest, access control or backups: copy the `.db` file (and its `-wal` file) yourself.

### PostgreSQL (shared or deployed)

Set `DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DBNAME` (from your host's secret manager, never from the repository).
The URL is rewritten to use the bundled `psycopg` 3 driver. The pool uses `pool_pre_ping` and recycling, so a database
restart is survived without restarting the backend: requests get a 503 while it is down and succeed again once it is back.
`GET /api/system/database` (administrators only) shows the redacted URL, the dialect, the schema version and row counts,
and nothing else about the server.

`APP_ENV=production` **refuses to start with SQLite**, because a deployed service's own disk is ephemeral (Render's free
web service, for one, loses it on every deploy and restart). Create a managed PostgreSQL database with whichever provider you
use and give its URL to the service. The ML model file (`ml/artifacts/`) is derived data that is retrained at start-up, so an
ephemeral disk is acceptable for it; sessions, events, alerts, investigations, containment records and simulation runs are
all in the database.

Moving the local demo data into PostgreSQL (copies every table, never writes to the source, refuses a non-empty target, runs in
one transaction, resets the id sequences, then compares row counts):

```powershell
$env:TARGET_DATABASE_URL = "postgresql://USER:PASSWORD@HOST:5432/DBNAME"      # bash: export TARGET_DATABASE_URL=...
python -m backend.db_tools copy --source sqlite:///./data/insider_threat.db
python -m backend.db_tools info --url $env:TARGET_DATABASE_URL                # schema version and row counts
```

A source file made by an older release must first be upgraded: `python -m backend.db_tools upgrade --url sqlite:///copy-of-it.db`
(work on a copy). Or skip the copy and let the new database seed itself (`AUTO_SEED=true`, which in production also needs
`DEMO_PASSWORDS_JSON`).

### Schema versions and migrations

`backend/migrations.py` keeps a `schema_migrations` table and applies numbered steps in a single transaction, under a lock
(`BEGIN IMMEDIATE` on SQLite, a PostgreSQL advisory lock), so two backends starting together cannot both migrate.

* A new database is created at the current version directly. An unversioned database from an earlier release is treated as
  version 1 and upgraded. A database **newer** than the code is refused untouched.
* Version 2 adds the indexes, the event de-duplication key and the constraints listed below. Before adding the uniqueness
  rules it repairs existing rows without deleting any: duplicate request ids and containment keys are cleared, extra open alerts
  and investigations are marked resolved, extra active controls are released, and an audit entry
  `schema_migration_repair` records the counts. If existing rows break a CHECK constraint the migration stops before
  changing anything and lists them. On SQLite the affected tables are rebuilt (copy, drop, rename, re-index, then
  `PRAGMA foreign_key_check`).
* Version 3 renames the two columns that called a heuristic score a "confidence" (`security_alerts.attack_confidence` to
  `peak_risk_score`; `attack_investigations.confidence`, a 0-1 fraction, to `risk_score_exact`, multiplied by 100 so it is a 0-100
  score like the others) and adds `impact_severity` and `evidence_strength` (on risk assessments, alerts and investigations) and
  `score_basis` (alerts). Old rows keep their scores; the new columns are empty and shown as "Not assessed". The rename also runs
  first in versions 1 and 2, so a database from before versioning is upgraded in one pass without losing the old values.
* There are no automatic downgrades. Back up before upgrading a database you care about.

### Constraints and indexes

Chosen from the queries the code actually runs (per-employee time windows for correlation and baselines, "last N days"
counts, the live feed, alert and investigation lists, evidence by address and session, simulation runs):

| Table | Indexes (besides primary and foreign keys) | Constraints |
|---|---|---|
| `security_events` | `(employee_id, timestamp)`, `(event_type, timestamp)`, `(timestamp)`, `(source_ip, timestamp)`, `(session_id)`, `(simulation_run_id)`; **unique `(employee_id, request_id)` where `request_id` is not null** | `outcome` in success/failure/denied; record counts not negative |
| `risk_assessments` | `(employee_id, created_at)`, `(event_id)` | level is a known risk band; score 0 to 100 |
| `security_alerts` | `(status, severity)`, `(employee_id, status)`, `(investigation_id)`, `(updated_at)`, `(created_at)`; **unique `employee_id` where status is open or investigating** | known status and severity |
| `attack_investigations` | `(employee_id, status)`, `(updated_at)`, `(status)`, `(simulation_run_id)`; **unique `employee_id` where status is open or contained** | known status |
| `containment_actions` | `(employee_id, created_at)`, `(investigation_id)`, `(alert_id)`; **unique `idempotency_key`** | known status |
| `simulation_runs` | `(status)`, `(scenario)`, `(created_at)`; **unique `idempotency_key`; unique `active_slot`** (one active run) | known status and seed mode; step counts not negative |
| `response_controls` | **unique `(kind, value)` where active** (one live block or isolation) | known kind |
| `employees`, `employee_sessions`, `audit_logs` | username, code, department, token hash, session IP, audit action / actor / time | known role and status |

A test asks SQLite's `EXPLAIN QUERY PLAN` for 14 of these queries and fails if any is answered by a table scan.

### Event ingestion: transactions, de-duplication and concurrency

* **One transaction per event.** The event, its risk assessment, the alert, the investigation and their audit rows are
  committed together or not at all. A test injects a failure in scoring and again in alerting and checks that nothing is left
  behind and that the same key can then be used normally.
* **De-duplication key: `(employee_id, request_id)`.** The backend takes the key from an `Idempotency-Key` header (8 to 48 characters
  of letters, digits and `_ . : -`; anything else is ignored, not rejected) or the `request_id` field of `POST /api/events`.
  A repeat returns the original event with `duplicate: true` and stores and scores nothing. The unique index makes this
  hold even when two requests arrive at the same instant (the loser catches the integrity error and returns the winner's
  event). Events without a key are never merged.
* **Streamlit reruns and double clicks.** A rerun does not call the backend again for data already loaded in that page
  visit. For a button or form, the portal sends one idempotency key per action and reuses it for an identical action within
  `PORTAL_REPEAT_WINDOW_SECONDS` (3 s by default), so a double click, or a rerun that interrupts a request in flight, is
  recorded once. The trade-off is deliberate: the same document requested again after the window **is** a new event, and
  inside the window it is not.
* **Concurrency.** On SQLite the single write lock serialises writers. On PostgreSQL each ingestion first takes a row lock
  on the employee (and the creator of a created account) in id order, so the assessment sees every earlier event and the
  "is there already an open alert?" check cannot race; the unique indexes above are the backstop. The lock is
  `FOR NO KEY UPDATE`: an earlier, simpler `FOR UPDATE` deadlocked when six simulated logins for one employee ran at once on
  PostgreSQL (found by the tests below), because each transaction already held the shared foreign-key lock created by its own
  session insert. A deadlock, lock timeout or lost connection that still occurs returns **503 with `Retry-After`**, never a
  stack trace; a unique-constraint clash returns 409. Containment retries replay the stored action (HTTP 200).

### Bounded reads and refresh intervals

* The change token `GET /api/soc/version` polled by every SOC session is a fixed handful of indexed `max()` reads. It no longer
  counts whole tables (a test checks this).
* The overview's totals cover the last `DASHBOARD_WINDOW_DAYS` days and say so on the tiles; per-employee assessment only runs
  for employees with events in the correlation window; investigation and action summaries are grouped in SQL; list endpoints
  take a `limit` capped by `MAX_PAGE_SIZE`; the live feed pages with a keyset cursor (`before_id`, returning `has_more` and
  `next_before_id`) and a "Show 150 more events" button, up to 450 rows in the page.
* Refresh intervals are configuration (`SOC_REFRESH_SECONDS`, `SOC_CACHE_SECONDS`) with minimums so a typo
  cannot make a dashboard hammer the backend. Each refresh is one small request; panels are re-fetched only when the token
  moves (or when the cached copy is older than `SOC_CACHE_SECONDS`, because time windows slide).

### What was and was not verified

Run in this repository (`python -m pytest tests -q`, 567 tests): migrations on a fresh database, on a database from an earlier
release (including duplicate repair), and the refusal of a newer one; constraint and index behaviour; query plans;
de-duplication, 12-way same-key and 9-way different-key concurrent ingestion on SQLite; transaction rollback; the
bounded-query checks; two SOC sessions and a portal session seeing the same data; Streamlit reruns and double clicks against a
live backend; a forced kill of the backend during a running simulation (data kept, the run marked failed, the run slot freed);
containment and its idempotent retry surviving a restart; lock contention giving a 503 and recovering; the copy tool
SQLite to SQLite. `tests/test_postgres.py` additionally runs a real backend against an **embedded PostgreSQL 16.2** (the
`pgserver` package from `requirements-dev.txt`, started by the test; skipped if it is not installed): schema, indexes
and partial unique indexes, 16-way same-key and different-key concurrency, six concurrent attack sequences ending in one live
alert and one live investigation, restart persistence, the SQLite to PostgreSQL copy (then starting a backend on the copy),
and a database stop and start while the backend stays up (503, then recovery without restarting the backend).

**Not verified:** any managed PostgreSQL service (the embedded server is a stock PostgreSQL 16.2 with default settings, not your
provider's configuration); behaviour under real load, large volumes, or many simultaneous dashboard sessions; PostgreSQL with more than
one backend process (the rate limiters, the baseline cache, the model and the simulation runner are in-process, so run **one**
backend worker); migration of a very large database; backup and restore.

## Demo credentials

For local demonstration only; every account is synthetic. **The passwords are not in the repository.** They are random,
generated on your machine by `python app.py setup` (or on first start) into `data/demo_credentials.local.json`
(git-ignored), and shown by `python app.py credentials`. Sign in with the **Employee ID** (the username also works).
Emails are `<username>@westbridgebank.test`. The database stores only Argon2id hashes; the backend never logs or returns a
password. If you started an earlier version, the first start of this one replaces the old, published demo passwords in your
existing database with the new random ones (the audit log records `demo_credentials_synced` with a count only). Passwords
that were committed to earlier versions of the repository remain in its git history and must be treated as public.

| Employee ID | Username | Name | Department / job role | Access (resource: level) | Registered IP(s) |
|---|---|---|---|---|---|
| `EMP-1001` | `alice.morgan` | Alice Morgan | Finance / Financial Analyst | Financial Reports rw, Customer Accounts r, Wiki r | 10.20.1.11, 10.20.1.12 |
| `EMP-1002` | `bob.chen` | Bob Chen | Finance / Payroll Specialist | Payroll Records rw, Financial Reports r, Wiki r | 10.20.1.21 |
| `EMP-1003` | `carol.diaz` | Carol Diaz | HR / HR Manager | HR Records rw, Payroll Records r, Wiki r | 10.20.2.31, 10.20.2.32 |
| `EMP-1004` | `david.kumar` | David Kumar | IT / Systems Administrator | IT Admin Console rw, Source Code r, Wiki rw | 10.20.3.41 |
| `EMP-1005` | `emma.wilson` | Emma Wilson | Trading / Risk Analyst | Trading Reports rw, Financial Reports r, Wiki r | 10.20.4.51 |
| `EMP-1006` | `frank.osei` | Frank Osei | Customer Service / Account Manager | Customer Accounts rw, Wiki r | 10.20.5.61, 10.20.5.62 |
| `EMP-1007` | `grace.lee` | Grace Lee | Compliance / Compliance Officer | Audit Reports rw, Financial Reports r, Customer Accounts r, Wiki r | 10.20.6.71 |
| `EMP-1008` | `henry.novak` | Henry Novak | Engineering / Software Engineer | Source Code rw, Wiki rw | 10.20.7.81 |
| `EMP-1009` | `isla.murphy` | Isla Murphy | Lending / Loan Officer | Loan Applications rw, Customer Accounts r, Wiki r | 10.20.8.91 |
| `EMP-1010` | `jack.silva` | Jack Silva | Marketing / Marketing Coordinator | Marketing Assets rw, Wiki r | 10.20.9.101 |
| `SEC-9011` | `soc.admin` | Sam Okafor | Security / SOC Analyst (**security administrator**) | Audit Reports r, Wiki r; SOC dashboard | 10.20.10.5 (also 127.0.0.1 and ::1) |

Every employee can also reach the self-service pages (own profile and payslips, directory, document library). The HR
manager sees HR records, the payroll specialist the payroll register and export, and the IT administrator can create
privileged accounts; the security administrator is the only role that can open the SOC dashboard.

## Launching the application

```powershell
python app.py all           # backend + portal + SOC dashboard
python app.py               # backend only
python app.py portal        # one dashboard (needs the backend running): portal | soc
```

Stop with Ctrl+C. All state stays in `data/insider_threat.db`.

## Deploying to the cloud

> **Status: prepared and rehearsed locally; not deployed.** No hosting account was available, so this repository contains no live
> URL and none is claimed. The Dockerfile and [render.yaml](render.yaml) have never been built or applied. Run the checks in
> [docs/deployment.md](docs/deployment.md#5-required-checks-after-deploying) against your own deployment before relying on it.
> This is an educational demo with synthetic data, not production banking security.

The platform is three processes (the FastAPI backend and two Streamlit apps) and one public port is available on most hosts,
so it deploys as **one Docker service**: [deploy/start.py](deploy/start.py) runs the three processes on loopback and
[deploy/gateway.py](deploy/gateway.py) is the only public listener.

```text
internet -> TLS (the host) -> gateway :$PORT --+-- /          employee portal
                                               +-- /soc/      SOC dashboard      (admin login at the gateway, then backend roles)
                                               +-- /healthz   backend and both apps
                                               +-- /api /docs /redoc /openapi.json -> 404 (the backend is never public)
```

* **Modes.** `DEPLOY_MODE=persistent` (default) stores everything in your PostgreSQL database (`DATABASE_URL`) and survives
  restarts. `DEPLOY_MODE=demo` uses a throw-away SQLite file that is re-seeded at every start and **refuses** `DATABASE_URL`, so
  demo data can never mix with persistent records. The container's disk is never used for durable data.
* **No default credentials.** Startup validation ([deploy/preflight.py](deploy/preflight.py)) exits with code 2, naming the
  missing settings (never their values), unless `SECRET_KEY` (32+ characters), `DEMO_PASSWORDS_JSON`, `ADMIN_UI_USER`,
  `ADMIN_UI_PASSWORD` (16+ characters) and an https `PUBLIC_URL` (Render supplies `RENDER_EXTERNAL_URL`) are set.
  `python -m deploy.make_secrets` generates them and prints to your terminal only.
* **Same backend for every dashboard.** The apps reach the backend through `API_BASE_URL` (production refuses to start
  without it; there is no localhost fallback outside development). CORS and the Streamlit websocket origin check allow only the
  public URL.
* **Model artifact.** The Docker build runs `python -m ml.train_model` (seeded synthetic data), so no model file is stored or
  downloaded.
* **TLS** is provided by the host (Render terminates HTTPS); the gateway redirects plain HTTP and sends HSTS only when the
  proxy reports https.

Steps that need **your** accounts (full detail in [docs/deployment.md](docs/deployment.md)):

1. Create a Render account and connect GitHub.
2. Create a Render PostgreSQL database and copy its URL (skip for `DEPLOY_MODE=demo`).
3. Run `python -m deploy.make_secrets` locally and keep the output.
4. *New > Blueprint* on this repository; [render.yaml](render.yaml) defines a Docker service on the 2 GB `1c-2g` plan (the
   processes needed about 0.6 GB while idle when there were four of them (measured on Windows; three need less, not re-measured), so 512 MB plans will not fit). Paste `DATABASE_URL`, `SECRET_KEY`,
   `DEMO_PASSWORDS_JSON`, `ADMIN_UI_USER` and `ADMIN_UI_PASSWORD` when asked (all `sync: false`, never stored in the repository).
5. Run `python -m deploy.verify --url https://<service> --gate-user ... --gate-password ...` for the public checks, and the
   behaviour and persistence checks from the Render shell with `--api http://127.0.0.1:8000`.

**What was verified locally** (Windows, not a deployment): the whole stack through `python -m deploy.start` in demo mode and in
persistent mode on a real embedded PostgreSQL 16 server, 25 of 25 `deploy.verify` checks, a hard kill and restart with 3 of 3
persistence checks, a clean-virtualenv install of [requirements-deploy.txt](requirements-deploy.txt), browser sign-in through
the gateway, a double-clicked download stored once and reloads storing nothing, a Streamlit websocket accepted for the public
origin and refused for another, and no secret in the logs. **Not verified:** the Docker build, Render itself, Linux
memory or load, real TLS behaviour, and anything on a public URL.

**Other layouts.** On one VM you can still run `python app.py all` behind your own HTTPS reverse proxy (WebSocket support
required) with `APP_ENV=production`, a random `SECRET_KEY`, `DEMO_PASSWORDS_JSON` (or `AUTO_SEED=false`) and PostgreSQL in
`DATABASE_URL` (or `ALLOW_SQLITE_IN_PRODUCTION=true` for one process on a persistent disk). Keep the backend on `127.0.0.1`,
and you must add your own authentication in front of the SOC pages. Hosting the dashboards on Streamlit
Community Cloud and the API elsewhere is possible (set `TRUSTED_FRONTEND_KEY` to the same random value on the API and every
dashboard so requests are attributed to the employee's registered workstation) but is not covered by the blueprint, and
Vercel cannot host this architecture at all (long-running processes, WebSockets, no persistent filesystem).

## How to exercise the platform

The platform reacts to **real requests**. There is no attack generator inside the product and no administrator console that writes
events: the portal, the API and the defences below are the only sources. To watch them work, use the **attack drill**, an ordinary
command-line client that sends real HTTP requests to the running backend, the way attacker tooling or a misbehaving employee would
(the scenario generator that used to live in the product is now an offline test tool; see [the offline scenario lab](#the-offline-scenario-lab)).

```powershell
python app.py setup && python app.py all          # .env gets a random TRUSTED_FRONTEND_KEY; leave this running
python -m deploy.attack_drill brute-force         # in a second terminal
```

| Command | What it sends | What the platform does |
|---|---|---|
| `brute-force` | five wrong passwords for `EMP-1010` from outside address `203.0.113.50` | records every attempt, locks the account, revokes its sessions, raises an incident with the five attempts as evidence |
| `credential-stuffing` | one common password against all 11 accounts from `198.51.100.77` | raises an incident, then refuses that address in this application's login code (not a firewall rule) |
| `idor` | `EMP-1003` requests ten other employees' records one by one | every request is refused (no data returned), recorded, raised as probing, and the account is locked at the Alert level |
| `bulk-export` | `EMP-1001` asks to export 15,000 records | held (HTTP 409) until a security administrator approves it in *Authentication Defence*; approval is single-use |
| `compromised-account` | `EMP-1001`'s valid password used from an address it has never used: probes five restricted resources, then two 9,000-record exports | goes through the normal event pipeline: baseline, rules, anomaly model, correlation, risk score; the detector decides whether to raise an alert and an investigation |
| `recover` | (as the SOC administrator) unlocks accounts and unblocks addresses | returns the demo to a clean state |

Every call is a genuine request to the real endpoints; what you see is the backend's own answer, and no event is flagged as test
data. Outside addresses are RFC 5737 documentation addresses. A client address is believed only together with the shared
`TRUSTED_FRONTEND_KEY` (the drill reads it from `.env`), which is how the backend tells an attacker's address from the machine you
are sitting at; without it every browser on one machine looks like the employee's own workstation. Employee passwords come from the
local demo credentials file and stand in for stolen ones. Point the drill only at your own backend. Order matters a little: the sign-in
throttle remembers a failed account for five minutes, so `credential-stuffing` right after `brute-force` shows HTTP 429 for `EMP-1010`.

**Self-checking version.** `python -m deploy.verify --api http://127.0.0.1:8000 --employee-password ... --admin-password ... --frontend-key ...`
runs held-export, approval and lock checks and prints PASS or FAIL for each.

**In the browser, as a second person.** Run `python app.py all` and keep the SOC dashboard open at http://127.0.0.1:8503. The portal
treats a browser on this machine as the employee's own workstation (that is what makes normal use look normal), so wrong passwords
typed at `http://localhost:8501` are recorded but are not an attack: failures from an account's own known address need 10 to count as
brute force, and the older sign-in throttle already answers HTTP 429 after 5. To be someone else, open the portal through this machine's
network address instead, for example `http://192.168.0.107:8501` (find yours with `ipconfig`), or from a phone on the same Wi-Fi.
The portal then reports that address to the backend, which sees an address the account has never used: five wrong passwords for
`EMP-1010` lock the account and raise the incident, and the SOC page shows the attempts from that address. The address is the real
network address of the browser, not something typed in a form; the backend believes it only together with `TRUSTED_FRONTEND_KEY`.
Windows may ask to allow Python through the firewall for network access; it is not needed for `localhost`.

**Bulk export by hand.** As `EMP-1001`, `POST /api/resources/financial-reports/access` with
`{"action": "export", "record_count": 12000}` returns HTTP 409 and creates a request. In *Authentication Defence*, approve it with a
note, then repeat the call with `"approval_id": <id>`: it succeeds once and the approval is spent.

## The offline scenario lab

The earlier seeded scenario generator lives in `lab/` (`scenario_generator.py` plans a run from a seed, `simulation_runs.py`
runs it, `simulation_service.py` holds the manual steps and the reset, `simulation_routes.py` is its API). It feeds synthetic
actions through the same ingestion functions the API uses and never writes an alert or a score itself. It is **not part of the
product**:

* its routes are mounted only when `LAB_MODE=true` (the test suite and `python -m ml.calibrate_scoring` set it);
* the backend **refuses to start** with `LAB_MODE=true` when `APP_ENV=production`;
* the `lab/` folder is not copied into the container image (a test builds that copy and checks it), so a deployed service has no
  such routes and no way to turn them on;
* there is no user interface for it any more.

Scenarios (benign activity, benign high-volume transfer, gradual collection and staging, bulk export, suspicious external
transfer, removable media, several weak signals, and the compromised-account campaign) use seeds, so the same seed, scenario and
employee give the same plan (its SHA-256 is stored). External addresses come from the RFC 5737 documentation ranges, destinations
end in `.invalid`, and the lab makes no network connection (a test fails if it tries).

To reset lab data in a development database: `POST /api/simulation/reset` as an administrator (409 while a run is active). It
removes every synthetic event, session, alert, investigation, assessment, privileged account, response control and lab run
record and undoes containment applied to the affected employees; real (non-synthetic) data is not touched, and the reset is
audited.

## Demo script (about 10 minutes)

Say at the start: *"This is a research platform on synthetic employees and data. It watches the requests it actually receives and
enforces its decisions itself: it locks accounts, refuses addresses and holds exports inside this application. It does not control a
firewall or a network, and it has not been validated on real traffic."* Then:

1. `python app.py setup`, then `python app.py all`. Open the SOC dashboard (http://127.0.0.1:8503) as `SEC-9011` (see
   `python app.py credentials`) and go to *Authentication Defence*. It is quiet. Open the portal (8501) beside it as an employee.
2. In a second terminal run `python -m deploy.attack_drill brute-force`. Refresh *Authentication Defence*: a locked account, an incident
   whose evidence is the five attempts with their times and address, the threshold and window, the automatic response (policy,
   who or what acted, expiry) and the statement of what it does not do. Try to sign the employee in with the right password: refused.
3. Unlock the account in the SOC page with a reason. Show the response history and the *Audit Logs* page.
4. Run `credential-stuffing`: one incident across many accounts, then the address refused by this application.
5. Run `idor` (probing other people's records: nothing returned, everything recorded, account locked) and `bulk-export` (HTTP 409, then
   approve it in the SOC page and show that the approval can be used once).
6. Run `compromised-account`. This is the insider-threat path: open *Live Event Feed*, *Employee Risk Monitor* and *Attack
   Investigations* to show the evidence, the explanation, the heuristic risk score (not a probability), the impact severity and the
   evidence strength. In the investigation, use **Run containment**; read the confirmation panel, tick it, run it, and show
   "Containment completed", the history row and the audit entry.
7. `python -m deploy.attack_drill recover` to reset the demo.

Avoid saying "the attack was blocked at the network", "this protects the bank" or quoting the benchmark figures as a guarantee; see
Known limitations and `docs/detection-evaluation.md`.

## How it works, end to end

1. **Sign in.** The portal posts the employee ID and password to `POST /api/auth/login`. The backend looks the employee
   up, verifies the Argon2id hash (a dummy hash is checked for unknown IDs so timing does not reveal whether an ID exists),
   refuses blocked IPs and locked accounts, opens a session, returns a random token and records a `login` event (or a
   `login_failed` event with the reason: `bad_password`, `ip_blocked`, `account_locked`).
2. **Authenticated requests.** Every later call carries `Authorization: Bearer <token>`. The backend hashes the token
   with HMAC, finds the session, and rejects it if it is unknown, revoked or expired (401), if the account is locked
   (403) or if the caller's IP is blocked (403). The *employee, session, IP and device used for events all come from this
   context*, never from the request body.
3. **Resource access.** For every view, download or export the backend checks the permission table
   (`view`/`download` need `read`, `export` needs `write`; self-service pages are open to every employee; an *isolated*
   system denies everyone). The result (`success` or `denied`) is stored as an event with the number of records involved.
4. **Detection.** Each stored event is run through the pipeline (rules, baseline, ML, correlation, risk score, band, impact,
   evidence strength, exposure) and gets a risk assessment row. Nothing is scored in the browser.
5. **Alert and investigation.** When the risk band reaches Alert (score at or above its threshold and at least three independent
   attack stages), a `security_alerts` row is
   written (with evidence, exposure and recommended actions) and an investigation is opened or updated.
6. **Response.** An administrator reviews the investigation in the SOC dashboard and chooses **Run
   containment**. The backend edits this application's own records, records the alert/investigation, the requested action,
   the administrator, the time and the result, and writes an audit log; the next login or request from the affected account
   or IP is refused by this backend. No external system is involved.
7. **Evidence.** The administrator downloads a JSON or CSV report that contains only that investigation's evidence.

### How the three screens stay in sync

The SOC dashboard checks `GET /api/soc/version` every `SOC_REFRESH_SECONDS` (3 by default). That endpoint returns a small change
token built from the latest event, assessment, audit, alert and investigation IDs and update times, plus the active
response controls and employees (a fixed handful of indexed reads, not table scans). The page only reloads its data when the
token changes, so filters, selected investigation and navigation are preserved while new events appear. All sessions read the
same database through the same backend, so two open SOC sessions and the portal stay consistent.

## The data

There are **two separate synthetic datasets**, both generated locally with fixed random seeds so results are repeatable.

### 1. Demo database (what you see in the dashboards)

Generated by `data/seed_data.py` (random seed `20260101`) the first time the backend starts.

* **10 employees plus 1 security administrator** across Finance (2), HR, IT, Trading, Customer Service, Compliance,
  Engineering, Lending, Marketing and Security, each with a role, department, registered workstation IPs, a unique
  password hash and a set of resource permissions (see the credentials table).
* **A catalogue of 15 resources** (`backend/catalog.py`), each with a sensitivity level and owning department:

  | Sensitivity | Resources |
  |---|---|
  | 1 internal | Internal Wiki, Marketing Assets, and the self-service pages My Profile, My Payslips, Employee Directory, Document Library |
  | 2 confidential | Financial Reports, Customer Accounts, Trading Reports, Loan Applications, Audit Reports, Source Code Repository |
  | 3 restricted | Payroll Records, HR Records, IT Admin Console |

* **14 days of normal history** (weekdays only, `HISTORY_DAYS = 14`) per employee: a login around 08:30 (plus or minus
  36 minutes) from a registered IP, 3 to 6 resource actions spaced 20 to 90 minutes apart (80% views of 1 to 20 records,
  20% downloads of 1 to 60 records, only on resources the employee is permitted to use), and a logout around 17:00.
* **Realistic noise** so the baseline is not artificially clean: one weekday per travelling employee (Bob, Emma, Isla)
  uses a home/travel address (`82.45.113.20`, `92.118.30.7`, `203.0.113.58`) and does very little; one random day per
  employee starts with a single mistyped password (a failed login one minute before the successful one). The seeded
  history has no after-hours sessions; those appear only in the ML dataset.
* Seeded events are stored with `evaluate_alerts=False`: rule flags are saved but no ML scoring or alerts are produced,
  so seeding never creates alerts.
* Everything created later by the offline scenario lab is flagged `is_synthetic = true` (events also carry `"synthetic": true` in
  their metadata) and is removed by the lab's reset (`POST /api/simulation/reset`, `LAB_MODE=true` only). Seeded history is also synthetic data, but it is the "real"
  baseline from the application's point of view and is never touched by reset.

### 2. Machine-learning training and evaluation dataset

Generated by `ml/synthetic_data.py` (random seed `42`) when the model is trained. It is independent of the demo
database, so the model never sees the demo attack and the demo attack never leaks into the baseline.

* **60 synthetic employees** (`SYN-001` to `SYN-060`) in 9 departments (7 each in Finance, HR, IT, Trading, Customer
  Service and Compliance; 6 each in Engineering, Lending and Marketing).
* Each employee gets a **28-day weekday history** that defines a personal baseline (known IPs, typical resources,
  usual hours, usual download sizes), followed by **35 days of sessions**.
* A **window** is one session (everything one employee did between sign-in and sign-out). The feature extractor turns
  each window into a vector of 10 numbers. In total: **2,047 windows built from 15,795 events** (about 7.7 events each).

**Normal behaviour modelled in every normal session**

| Behaviour | Frequency / size |
|---|---|
| Login at business hours from a registered IP | the default |
| After-hours session (weekend or outside 07:00-19:00) | 6% |
| Login from an outside IP (documentation ranges `198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`) | 5% |
| One or more failed logins before success (mistyped password) | 6% |
| Resource views per session | 3 to 8; 20% are self-service pages |
| Downloads | 1 to 80 records; 2% are "heavy but plausible" at 150 to 420 records |
| Honest denied attempt (clicked something not permitted) | 4% |
| Small approved external transfer to `approved-partner` | 3% |
| Routine IT account creation by an IT employee in business hours | 2% |

**How the data is split**

| Subset | Windows | Content |
|---|---|---|
| Training set | 1,208 | **normal windows only** (an `assert` in `ml/train_model.py` enforces `label == 0`) |
| Test set, normal | 479 | 292 ordinary; 60 each of `after_hours_only`, `unfamiliar_ip_only` and `heavy_but_plausible_download`; 7 `legit_admin_work` (IT only) |
| Test set, attack | 360 | 60 each of `restricted_probe`, `bulk_export`, `brute_force`, `privileged_account`, `external_transfer` and `full_chain` |

The *hard normal* scenarios (after-hours only, unfamiliar IP only, heavy but plausible download, legitimate admin work)
exist specifically to measure false positives: behaviour that is unusual but innocent and must not become an attack.
Attack windows are used **only for evaluation**, never for training.

## Machine learning in detail

* **Algorithm:** scikit-learn `IsolationForest` (`n_estimators=300`, `max_samples=min(256, n)`,
  `contamination="auto"`, `random_state=seed`). It isolates points with random splits; points that are isolated quickly
  are unusual. It needs no attack labels, which is why it can be trained on normal behaviour alone.
* **One feature pipeline** (`ml/features.py`) is used for training, scoring live sessions and the fallback, so they can
  never drift apart. The 10 features of a session window:

  | # | Feature | Meaning |
  |---|---|---|
  | 1 | `login_hour` | local hour of the session's first event |
  | 2 | `unfamiliar_ip` | 1 if an IP is outside the employee's baseline IPs |
  | 3 | `failed_login_count` | failed logins in the window |
  | 4 | `resources_accessed` | distinct resources touched |
  | 5 | `departments_accessed` | distinct departments whose resources were touched |
  | 6 | `download_volume` | records downloaded or exported, `log1p`-scaled |
  | 7 | `restricted_access_attempts` | denied attempts, or first-time restricted access outside the employee's normal duties |
  | 8 | `privilege_escalation` | 1 if accounts or permissions were changed |
  | 9 | `external_transfer_volume` | records sent outside, `log1p`-scaled |
  | 10 | `denied_access_count` | permission denials |

* **From raw score to 0-1 anomaly score.** The raw score is `-score_samples` (higher is more abnormal). It is calibrated
  against the training data: `lo` is the 90th percentile of training raw scores, `hi = lo + 0.16`, and the anomaly
  score is `(raw - lo) / (hi - lo)` clipped to 0-1. So an ordinary session scores about 0 and a clearly abnormal one
  approaches 1. The calibration, feature names, metrics, scikit-learn version and seed are stored with the model.
* **Saved locally** to `ml/artifacts/isolation_forest.joblib` (git-ignored) and loaded at start. If it is missing it is
  trained automatically (`ML_AUTO_TRAIN`). `POST /api/detection/retrain` retrains on demand.
* **Fallback mode.** If the file is missing, corrupt, from an incompatible scikit-learn version, or its feature names do
  not match, the engine uses `heuristic_score` instead: a noisy-OR of bounded terms over the same features. The
  application keeps working, `GET /api/detection/status` reports which mode is active.
* **Volume guard.** An Isolation Forest cannot extrapolate: a download 50x larger than anything in training lands in the
  same outer leaf as one 3x larger, so a bare bulk export barely moved its score (3.3% recall in the first version).
  The saved model therefore also stores the largest `download_volume` and `external_transfer_volume` seen in normal
  training sessions, and the anomaly score is `max(forest score, volume guard)`. The guard is 0 up to 2x that maximum
  and rises linearly (in log units) to 1 at about 10x further. It is monotonic and has no effect on ordinary sessions.
  Models saved without a reference (older files) are still loaded and simply have no guard.
* **Measured on the held-out synthetic test set (839 windows)** with the model produced by `python -m ml.train_model`:

  | Metric | Value |
  |---|---|
  | ROC-AUC | 0.992 |
  | False positives on all normal windows | 2.4% |
  | False positives on hard normals | 6.4% (unfamiliar IP only 11.7%, heavy plausible download 5.0%, after-hours only 3.3%, legitimate admin work 0%) |
  | Attack recall, Isolation Forest alone | 83.9% (`bulk_export` 3.3%) |
  | Attack recall, forest plus volume guard | 100% in every attack scenario |
  | Mean anomaly score | normal 0.027, attack 0.905 |

  The guard's headroom and span were chosen after seeing that the forest alone missed bulk exports, and the attack sizes
  in the synthetic data (3,000 to 50,000 records) are ones I generated, so the 100% recall is an optimistic, in-sample
  figure. It says nothing about real banks. The first external check is the evaluator below.

### Evaluating on a dataset this project did not generate

`ml/evaluate_dataset.py` scores the saved model on any event-level CSV, using the same feature pipeline as the live
system. It does not train anything.

```powershell
python -m ml.evaluate_dataset --events path\to\events.csv --history-days 28 --out report.json
```

Required columns: `employee_id`, `timestamp`, `event_type`, `source_ip`. Optional: `resource`, `outcome`,
`records_accessed`, `records_downloaded`, `session_id`, `department`, `label` (0/1 per event) and `scenario`. Event types
and resource ids must be the application's (see `backend/catalog.py`); `--resource-map map.json` renames resources.
Each employee's first `--history-days` days become the baseline, later events are grouped into sessions, and the report
gives ROC-AUC, false-positive rate and recall at the chosen threshold (and recall per `scenario`) when labels exist, or
just the score distribution when they do not. `tests/test_hardening.py` runs it on a CSV generated from the synthetic
generators, which proves the plumbing only, not real-world accuracy.

### The CERT Insider Threat Test Dataset (external benchmark) and a separate synthetic supplement

The project has a repeatable pipeline for the **CERT Insider Threat Test Dataset, release r4.2** (Carnegie Mellon
University SEI CERT Division with ExactData, LLC; CC BY 4.0; <https://sei.cmu.edu/library/insider-threat-test-dataset/>).
**It is synthetic** (generated background users plus synthetic malicious actors) and is *not* real banking data; no
figure derived from it describes a real organisation. It is not included in the repository and is never committed or
uploaded: you download it yourself, verify the checksums and process it locally. Full instructions, the exact file
layout, the source-field mapping, the label rules and the caveats are in [docs/cert-dataset.md](docs/cert-dataset.md).

```powershell
python -m ml.cert.validate  --source data/external/cert/r4.2 --answers data/external/cert/answers-extract/answers
python -m ml.cert.prepare   --source data/external/cert/r4.2 --answers data/external/cert/answers-extract/answers --out data/processed/cert_r4.2
python -m ml.cert.synthetic --out data/processed/synthetic_test --seed 42 --profile data/processed/cert_r4.2/cert_profile.json
```

What the pipeline guarantees: the original files are never modified; events, ground-truth labels, evaluation metadata and
display fields are stored separately; labels follow the official answer key event by event (a malicious user's other
events are *not* labelled malicious, and events the key lists under another account are treated as ambiguous and
excluded from metrics); users are split into train/validation/test as whole users; `ml/cert/leakage.py` rejects labels,
identities, answer-key fields and synthetic events as model inputs; and a synthetic supplement (`source = synthetic_test`,
fixed seed or recorded random seed, manifest with the reason for every scenario) is kept apart from the CERT test set.
This step prepares data only; the detection benchmark built on it is described next.

### Detection benchmark: features, models, results and limits

`ml/detect/` turns events into per-user, per-day windows, builds deviation features (own history, a lagged own
baseline, peer group, 7-day change, sustained-drift CUSUMs, sequences), compares several detectors and scores them on
held-out users. The *live* application engine above is unchanged apart from the new states and audit view; this pipeline is
an offline benchmark, not wired into live scoring. Everything is in [docs/detection-evaluation.md](docs/detection-evaluation.md)
with full tables in [docs/detection-results/](docs/detection-results). The headline numbers, all on **held-out test users**
with the threshold calibrated on validation users only (test evaluated once):

| CERT r4.2 (synthetic data), 21 insiders | Precision | Recall | F1 | FPR | Incidents detected |
|---|---|---|---|---|---|
| Original approach (Isolation Forest, raw volumes) | 0.013 | 0.018 | 0.015 | 0.0040 | 4 / 21 |
| Isolation Forest on the new deviation features | 0.150 | 0.149 | 0.150 | 0.0024 | 19 / 21 |
| Hybrid (rules + correlation + anomaly model) | 0.170 | 0.229 | 0.195 | 0.0032 | 13 / 21 |
| Hybrid without the destination-category enrichment | 0.117 | 0.120 | 0.119 | 0.0026 | 16 / 21 |
| Supervised reference (uses labels; a ceiling, not a deployable detector) | 0.291 | 0.993 | 0.450 | 0.0070 | 20 / 21 |

What these numbers do and do not show:

* The new features and the hybrid are about an order of magnitude better than the original raw-feature model, but the
  unsupervised detectors are still far from the supervised reference, and precision is low. r4.2 is a "dense needles" dataset
  (0.29 % of test windows are malicious), so precision and F1 are inflated relative to a real organisation. Intervals are wide
  (21 insiders): the hybrid's recall 95 % interval is 0.08 to 0.38.
* **Bulk export (separate synthetic report; CERT r4.2 has no bulk-export scenario):** the original raw-feature model detected
  0 of 7 held-out bulk-export incidents; the hybrid detected 6 of 7 with **0 false alerts on benign large transfers**, while
  LOF and the supervised model both alerted on 3 of 3 legitimate large transfers. The hybrid missed `unusual_external_transfer`
  (0 / 4) and 4 of 7 `account_misuse` incidents. Synthetic and CERT numbers are never combined.
* **Early warning holds only for long incidents.** Windows are scored at day end. For CERT scenario 2 (about 55 days) the hybrid's
  median alert came 16 days after the first malicious event with 62 % of the incident's events still to come; for single-day
  patterns, and for scenario 3 (about 1.4 days), the alert came after most or all of the activity. The live application engine
  alerts event by event before the final simulated transfer, but this benchmark does **not** demonstrate early detection of a
  single-day bulk export.
* The destination-category lists (job-search, file-sharing, document-leak sites) were written after reading the public
  scenario descriptions, so the results with them are optimistic; the no-category row is the conservative figure.
* Not computable: per-scenario precision (benign windows have no scenario), a bulk-export result on CERT, precision at real-world
  prevalence, and delay for undetected incidents. Labels outside the answer key are benign only by convention.

**The five states in the application** (SOC overview and every investigation page): *anomalous activity detected*, *suspicious
sequence correlated*, *potential data exposure*, *confirmed malicious (simulation ground truth)* and *simulated containment
completed*. Model outputs are never shown as confirmed; "confirmed" exists only where the simulation provides ground truth,
and the live engine's two score components and every piece of evidence behind them are itemised on the investigation page
([How the scores are defined](#how-the-scores-are-defined)).

### Rigorous evaluation (one command)

`python -m ml.detect.run_evaluation --cert-processed data/processed/cert_r4.2 --out reports/evaluation --partition test --final`
re-evaluates every detector with user-disjoint **and** time-ordered splits, fitting and calibrating on train/validation only,
and writes `report.md`, `results.json`, `manifest.json` and per-track CSVs to [reports/evaluation/](reports/evaluation). It
reports three separate tracks (held-out CERT, project-generated synthetic scenarios, hand-built unit scenarios) and
deliberately gives no combined score. Compared with the original raw-volume Isolation Forest, the deviation-feature models and
the hybrid are better on all three tracks, but CERT precision stays low (hybrid window-level F1 0.175, original 0.021, supervised
reference 0.208), and the hybrid missed both scenario-3 incidents. The CERT test users were already used once in the earlier
benchmark, so this is a later time slice of the same users, not a fresh set. Details, caveats and the leakage tests are in
[docs/detection-evaluation.md](docs/detection-evaluation.md#10-rigorous-evaluation-protocol-one-command).

## Authentication defence: real sign-in monitoring and response

This is built on the real sign-in endpoint (`POST /api/auth/login`), not on the simulation. Every attempt that reaches the backend
is stored in `auth_attempts` (success, failure, or denied because the address is blocked or the account is locked). An unknown
username is stored only as a keyed hash (`unknown:<12 hex>`), so a password typed into the wrong box is never kept, and the audit
log uses the same hash. Detection reads those stored attempts inside time windows, so counts survive a restart and are the same
on every backend instance (the older in-memory login throttle is unchanged and still answers 429). Real `401` and `403`
responses of the API are recorded too (`access_denials`: the route template, the identifier asked for, the trusted client
address and, when the token matches a session, the account; never a token, a body or a credential). Refusals caused by our own
enforcement (a locked account, a blocked address) are not counted, and at most `DENIAL_RECORD_LIMIT_PER_MINUTE` are stored per
address per minute so a flood cannot fill the database.

| Pattern | Default trigger | What the policy does automatically |
|---|---|---|
| Brute force on one account | 5 failures in 5 min (10 if every failure came from the account's own registered addresses) | Lock the account for 15 min and revoke its sessions |
| Credential stuffing | 5 different accounts failed from one address in 10 min: Elevated; 10 accounts or 20 failures: Alert | Alert only; at Alert, block the address for 60 min |
| Burst of failures from one address | 10 failures in 5 min: Elevated; 20 in 10 min: Alert | Alert only; at Alert, block the address for 60 min |
| One account attacked from many addresses | 6 failures from 3 or more addresses in 10 min | Lock the account for 15 min |
| Sign-in after repeated failures | 3 or more failures in 10 min, then a success from an address that is **not** registered to the account | Revoke sessions (the new one included, so no token is returned), lock the account, block the address |
| Repeated refused requests | 10 refusals (403) by one account in 5 min: Elevated; 30: Alert | At Alert, end the account's sessions and lock it |
| Probing other people's records (IDOR) | 5 different objects refused on one route by one account in 5 min: Elevated; 10: Alert | At Alert, end the sessions and lock the account |
| Flood of unauthenticated requests | 30 refusals (401) from one address in 5 min: Elevated; 100: Alert | At Alert, block the address for 60 min |
| Repeated bulk-export requests | 3 requests held for approval or refused in 30 min: Elevated; 6: Alert | At Alert, end the account's sessions and lock it |

Repeating one forbidden call is told apart from probing many different records, and probing is not also counted as plain
repetition. The refusals themselves come from the backend's authorization checks (the record is never returned); this adds the
trail and the response.

**Bulk exports and downloads** are authorized on the server **before** anything is processed (`backend/export_policy.py`), on every
real path: the resource-access API, the telemetry endpoint, the payroll export and document downloads. A request is allowed, or:
more than 10,000 records in one request is **held for approval** (a pending request, HTTP 409, no data returned); more than
100,000 in one request is **refused outright** (403, approval cannot lift it); and an account that would exceed its rolling
**hourly allowance** of 25,000 records is refused (429 with `Retry-After`). Large is not treated as malicious: staff with write access
in the resource's own department get 5 times the hourly allowance, and an approved request bypasses the hourly allowance (never
the absolute limit). A security administrator approves or denies on the SOC page; an approval is **single-use, bound to one
account, resource, action and size, and expires** (60 min by default), it cannot be decided by the requester, and nothing is
released by approving: the employee must repeat the request with `approval_id`. Employees can list their own requests at
`GET /api/portal/exports`. Simulation traffic is exempt because it never touches real data.

A success from the account's own registered address, while the failures came from other addresses, is the owner and raises nothing:
treating it as a takeover would punish the victim. A success from the owner's own address that also produced the failures
(typos) is flagged for review only. The bands are rule-based and **not probabilities**; every incident stores the thresholds
and the attempt ids it was built from, and shows them on the SOC page.

**What "blocked" and "locked" mean here.** Enforcement is real inside this application: a locked account cannot sign in or use any
token, and a blocked address is refused on every request (`get_auth`, `authenticate`). An address block is an
**application-level block, not a firewall rule**: it does not stop traffic reaching the host, and the SOC page says so. There is
no firewall integration in this phase.

**Safeguards.** Security administrators are never locked automatically (an attacker could lock the SOC out); loopback, private,
shared and link-local addresses, addresses in `PROTECTED_IPS` and any employee's registered address are never blocked; automatic
locks and blocks are capped per hour, beyond which the action waits for an analyst (`pending approval`); automatic locks and
blocks expire; a lock by an analyst never expires by itself; locking is a compare-and-set, so concurrent attempts lock once;
unlocking never restores sessions that were revoked. `AUTH_AUTO_RESPONSE=false` gives detect-only mode.

**Source address.** Clients cannot supply their address. The backend believes `X-Client-IP` only on a request that also carries
the shared `X-Frontend-Key` (`TRUSTED_FRONTEND_KEY`); the dashboards send it, taking it from the gateway, which overwrites anything
the browser sent and reads `X-Forwarded-For` only when `TRUST_FORWARDED_FOR=true` (set automatically on Render, where a proxy
is in front), and then only the last entry. In the single-container deployment the key is generated at each start. Locally there
is no gateway, so loopback requests are still attributed to the employee's registered workstation: to see unfamiliar addresses
locally, send `X-Frontend-Key` and `X-Client-IP` yourself, as `tests/test_auth_defense.py` does.

**SOC page and API** (security administrators only, enforced by the backend): the SOC dashboard has an *Authentication Defence*
page (incidents, evidence, locked accounts, blocked addresses, recent attempts, response history, unlock/unblock and manual
responses with a reason and confirmation). Endpoints under `/api/soc/auth`: `overview`, `incidents`, `incidents/{id}`,
`incidents/{id}/status`, `incidents/{id}/actions`, `attempts`, `denials`, `export-requests` (GET), `export-requests/{id}/decision`,
`actions` (GET) and `actions` (POST, direct response). State
changes are rate limited, validated, audited and idempotent with an `Idempotency-Key`.

| Setting | Default | Meaning |
|---|---|---|
| `AUTH_DEFENSE_ENABLED` / `AUTH_AUTO_RESPONSE` | `true` / `true` | Record and detect / apply the response policy |
| `ACCOUNT_LOCKOUT_THRESHOLD`, `ACCOUNT_FAILURE_WINDOW_MINUTES`, `KNOWN_IP_LOCKOUT_THRESHOLD`, `ACCOUNT_LOCK_MINUTES` | 5, 5, 10, 15 | One-account brute force |
| `IP_ALERT_FAILURES`, `IP_ALERT_WINDOW_MINUTES`, `IP_BLOCK_THRESHOLD`, `IP_BLOCK_WINDOW_MINUTES`, `IP_BLOCK_MINUTES` | 10, 5, 20, 10, 60 | One-address bursts and blocks |
| `STUFFING_ACCOUNTS_ALERT`, `STUFFING_ACCOUNTS_CRITICAL`, `STUFFING_WINDOW_MINUTES` | 5, 10, 10 | Credential stuffing |
| `DISTRIBUTED_IPS`, `DISTRIBUTED_FAILURES`, `DISTRIBUTED_WINDOW_MINUTES` | 3, 6, 10 | One account, many addresses |
| `SUCCESS_AFTER_FAILURES`, `SUCCESS_AFTER_FAILURES_WINDOW_MINUTES` | 3, 10 | Success after failures |
| `FORBIDDEN_ALERT`, `FORBIDDEN_CRITICAL`, `IDOR_DISTINCT_ALERT`, `IDOR_DISTINCT_CRITICAL`, `UNAUTH_FLOOD_ALERT`, `UNAUTH_FLOOD_CRITICAL`, `ACCESS_WINDOW_MINUTES`, `DENIAL_RECORD_LIMIT_PER_MINUTE` | 10, 30, 5, 10, 30, 100, 5, 120 | Refused requests (401/403) |
| `EXPORT_APPROVAL_THRESHOLD`, `EXPORT_HARD_LIMIT`, `EXPORT_HOURLY_LIMIT`, `EXPORT_OWNER_MULTIPLIER`, `EXPORT_APPROVAL_MINUTES` | 10000, 100000, 25000, 5, 60 | Export and download authorization |
| `EXPORT_ATTEMPT_ALERT`, `EXPORT_ATTEMPT_CRITICAL`, `EXPORT_ATTEMPT_WINDOW_MINUTES` | 3, 6, 30 | Repeated bulk-export requests |
| `MAX_AUTO_LOCKS_PER_HOUR`, `MAX_AUTO_BLOCKS_PER_HOUR`, `PROTECTED_IPS`, `AUTH_ATTEMPT_RETENTION_DAYS` | 10, 10, empty, 30 | Safeguards and retention |

These are starting values, not universal truth: calibrate them against your real sign-in traffic.

**What was verified.** `tests/test_auth_defense.py` (34 tests) drives the real login endpoint: recording and hashing of unknown
names, each detector and its thresholds, automatic lock, session revocation, expiry, address blocks and their expiry, private and
protected addresses, the administrator exemption, detect-only mode, the hourly caps, concurrent attempts (one incident, one
lock), recovery by an administrator, authorization (401/403), payload validation, idempotent replay, restart persistence, and the
schema 3 to 4 migration. `tests/test_access_defense.py` (15 tests) covers refused requests: what is and is not recorded, repeated
refusals, IDOR probing versus repetition, the unauthenticated flood and its block, our own enforcement not being counted, the
per-address cap, detect-only mode and authorization. `tests/test_auth_defense_ui.py` drives the real SOC page against a real
backend process (unlocking an account; IDOR evidence; approving a held export), and the page was also checked in a browser
against real failed sign-ins. `tests/test_export_defense.py` (16 tests) covers every export outcome: unaffected normal sizes,
held-for-approval, single-use approvals (including eight simultaneous uses of one approval), binding to account, resource,
action and size, denial and expiry, the absolute limit, the hourly allowance and the owner multiplier, the payroll export, the
incident and its response, authorization and validation, and the simulation exemption. **Not verified:** any public deployment, an attacker on a separate
device, behaviour on PostgreSQL with several instances (concurrency was tested on SQLite), the thresholds against real
traffic, or the gateway's address handling behind a real platform proxy.

**Not done in this phase** (still to build): a firewall provider integration (Vercel or another WAF) and its enforcement states,
Redis, detections for password changes and geolocation, a portal screen for employees to
track their own export requests (the API exists),
progressive login delays, analyst assignment, a Next.js front end, and calibration on real traffic.

## Detection rules in detail

The rules are data, not code: `backend/detection_rules.json` (19 rules, hot-reloadable). Every rule has a *weight*
between 0 and 1, assigned by hand, and, where relevant, an attack *stage*. The weight says how strongly that rule alone counts
as evidence; it is **not** impact severity and not a probability (older versions called it "severity"; the stored event flags
keep that key and expose it as `risk_points`, weight x 100). A rule only counts as evidence if its weight is at least
`min_evidence_severity` (0.10); weaker flags are kept on the event for context but do not add to the score.

| Rule | Weight | Stage | Fires when |
|---|---|---|---|
| `unfamiliar_ip` | 0.18 | Initial Access | a login or failed login comes from an IP outside the baseline; for other events once per IP per window |
| `off_hours_login` | 0.08 | none | login at a weekend or outside 07:00-19:00, **only** if the employee's after-hours rate is below 15% |
| `failed_login` | 0.05 | none | any failed login |
| `failed_login_burst` | 0.38 | Credential Misuse | 3 failed logins within 10 minutes |
| `admin_console_login_failed` | 0.45 | Credential Misuse | failed authentication to the administrator console |
| `login_after_failures` | 0.38 | Credential Misuse | a success after 3 failures within 30 minutes (possible guessed password) |
| `access_denied` | 0.06 | none | a denied access that is neither of the next two |
| `unauthorised_department_access` | 0.26 | Sensitive Resource Access | denied access to a confidential resource of another department |
| `restricted_denied` | 0.32 | Sensitive Resource Access | denied access to a restricted (level 3) resource |
| `sensitive_access_novel` | 0.12 | Sensitive Resource Access | restricted resource the employee never normally uses outside their own department |
| `rapid_enumeration` | 0.30 | Sensitive Resource Access | 5 or more classified resources touched within 10 minutes |
| `large_export` | 0.42 | Collection | export or download over `max(500, 3 x the employee's largest historical session download)` |
| `data_export` | 0.08 | none | any ordinary export (context only) |
| `removable_media_copy` | 0.34 (halved below the bulk threshold) | Collection | records of a classified resource copied to removable media (`details.channel = removable_media`); fires once per correlation window |
| `unusual_outbound_transfer` | 0.38 | Collection | an external transfer by an employee with no earlier transfers, or one at or above the large-export threshold |
| `external_transfer_confirmed` | 0.72 | Exfiltration | an external transfer that succeeded with status `confirmed` |
| `permission_change_attempt` | 0.40 | Privilege Escalation | a permission-change event, or a denied administrative action |
| `privileged_account_created` | 0.58 | Privilege Escalation and Persistence | a privileged account was created (scaled down for routine IT work) |
| `new_account_login` | 0.45 | Lateral Movement | login to an account created in the last 24 hours |

**Context decides, not the bare event.**

* A new IP alone is a weak signal (0.18). An employee logging in from a new address and opening a permitted document
  stays Normal or Watch; it is the combination with other stages that raises the score.
* `off_hours_login` is suppressed for people who regularly work late.
* `large_export` is relative to that employee's history, with a floor of 500 records.
* Denials caused by a SOC isolation (`reason = system_isolated`) are not scored against the employee.
* Routine IT account creation from a known IP in business hours is scaled by 0.45 (`legitimate_role_scale`).
* Contextual rules fire once per window (`_already_flagged`), so a repeated action does not keep adding.

## Baseline, correlation, scoring and data exposure

### Behavioural baseline (`backend/baseline.py`)

Built per employee from the previous `BASELINE_DAYS` (30) up to the start of the current correlation window, so
attacker activity can never become "normal". It holds the known IPs (registered IPs plus any IP with at least two
successful historical logins), the permissions, the typical resources, the after-hours rate, the largest and mean
per-session download, the number of earlier external transfers and logins, and the account age and whether another
employee created the account (which makes a new account's first logins suspicious).

### Correlation (`backend/correlation_engine.py`)

* Events are grouped inside a configurable window (`CORRELATION_WINDOW_MINUTES`, default 240).
* Events are linked when they share the **employee**, the **session**, an **unfamiliar IP**, or a **created account**:
  an account created by the employee is attributed back to its creator, so actions of `svc.backup01` count against the
  employee that made it.
* Each event is mapped to the attack stage(s) it supports. The eight stages are Initial Access, Credential Misuse,
  Sensitive Resource Access, Collection, Privilege Escalation, Persistence, Lateral Movement and Exfiltration. They are
  derived from the evidence **in any order**: no fixed sequence is required.
* **No double counting:** each event counts toward one independent stage; repeated evidence of the same kind is
  discounted by `repeat_factor` 0.25 up to `repeat_cap` 1.5; duplicate requests (same `request_id` or
  `Idempotency-Key`) are stored and scored once.

### How the scores are defined

An analyst sees four different things. **None of them is a probability**: this project has no labelled real-world incidents from
which a probability could be calibrated, so every number is either a model output on its own scale or a hand-assigned weight, and
the dashboards, API and exports say which (`GET /api/detection/status` returns these definitions, and the Overview shows them under
"How to read the scores").

| Quantity | Range | What it is | Where it comes from |
|---|---|---|---|
| **Heuristic risk score** | 0-100 | a hand-weighted evidence score used to rank activity | `100 x (0.80 x rule evidence + 0.20 x anomaly score)` |
| **Risk band** | Normal / Watch / Elevated / Alert | the score against calibrated thresholds, limited by independent attack stages | the operating point below; decides triage order and whether an alert is raised |
| **Impact severity** | None / Low / Medium / High / Critical | what the evidence shows was accessed, exported or changed | rules over the evidence only (below); never uses the score or the model |
| **Evidence strength** | None / Weak / Moderate / Strong | how well independent evidence corroborates the finding | attack stages spanned by rule evidence, and whether the anomaly model independently agrees |

Smaller numbers inside them: the **anomaly score** (0-1) is the Isolation Forest output rescaled against normal training behaviour
(the upper edge of typical behaviour maps to 0, a fixed span above it to 1, plus a guard for volumes beyond anything in
training); a **rule weight** (0-1) is a hand-assigned weight. Neither is a probability.

**The calculation, and why each piece is counted once** (`backend/scoring.py`, `backend/threat_engine.py`):

```
risk_score = 100 x ( 0.80 x rule_evidence + 0.20 x anomaly_score )          weights in detection_rules.json, sum to 1
```

* **Rule evidence** is a noisy-OR over evidence groups. An event is evidence **once**, through its strongest rule, however many times
  it appears. Events with the same rule on the same target form one group worth its strongest weight plus 25 % of each further
  weight (`repeat_factor`), never more than 1.5 times the strongest (`repeat_cap`). Different groups combine as `1 - product(1 - group)`,
  so many weak signals do not add up linearly.
* **The anomaly score** comes from a separate model. It sees the same events as the rules, so its share is small, and it never
  raises the corroboration gate.
* **Not added to the score:** attack stage, correlation strength and baseline deviation. An earlier version added them as three more
  components (and used 0.30/0.25/0.10/0.15 weights). They were functions of the same rule evidence, so one unfamiliar IP or one large
  export was counted by the rule, the stage, the correlation and the baseline. The independent-stage count now **gates the band**
  instead of adding points.
* **The gate:** the band implied by the score is lowered to Watch when fewer than 2 independent stages exist, and to Elevated when
  fewer than 3 exist. One loud signal, however strong, therefore cannot reach Alert alone. The score itself is not changed by the
  gate; the investigation page shows both ("band from the score alone" and "risk band").
* The whole-number score is floored so it never reads higher than the exact value.

**Impact severity** (rules in `scoring.impact_severity`, evidence only): *Critical* when an external transfer is confirmed, or a foothold
(persistence, lateral movement) exists next to a confirmed export; *High* at or above the bulk threshold of potentially exposed records
or when privileges were escalated; *Medium* for a confirmed export below bulk, suspicious access to sensitive records, credential
misuse, sensitive-resource access or collection; *Low* for other suspicious activity; *None* otherwise. Each result carries its reasons.

**Evidence strength:** *None* without rule evidence; *Strong* with at least 3 independent stages, or 2 stages when the model agrees;
*Moderate* with 2 stages, or 1 stage when the model agrees; otherwise *Weak*. The model "agrees" only when a trained Isolation Forest
is loaded and its anomaly score reaches `ML_CORROBORATION_THRESHOLD`; the heuristic fallback is never counted as corroboration.

**Severity is kept apart from certainty.** A bulk export of 25,000 records by one employee, with nothing else going on, is reported as
*High* impact, one attack stage, a Watch band and at most Moderate evidence: serious if true, uncertain whether it is an attack.
A chain of weak signals can be the opposite: Alert band and Strong evidence with only Low or Medium impact. The alert and the
investigation record all three, and `GET /api/alerts` filters on `risk_band` and `impact_severity` separately.

**What the analyst can inspect for any score** (investigation page, "How the heuristic risk score was built", and `GET /api/risk/employees/{id}`
as `score_breakdown`; the alert keeps the same structure as `score_basis` from when it was raised): the formula; each component with
what it is, its value, weight and points (they add up to the score); each rule evidence group with its weight, the weight counted,
the event references (`#id`) and the first and last time; the events that were considered and whether each was counted; the time
window; the model output (mode, score, raw score, volume guard); the feature deviations the model reacts to (records downloaded
against the employee's largest earlier session, unfamiliar address, restricted attempts, failed logins, departments, privilege
attempts, login hour against business hours and their own after-hours rate); the corroboration gate; the thresholds in force and
where they came from; and the reasons behind the impact and strength readings.

A typical simulated run (test clock pinned to 21:00 local, so the off-hours signal is present; the chain from
[the lab's attack stages](#the-labs-attack-stages-step-by-step)): the heuristic risk score goes 33.1 (unfamiliar login; band Normal at the
recorded thresholds, impact Low), 84.3 (restricted access; two stages, Elevated, impact Medium), **90.9 at the large export (three
stages, Alert, impact High; the alert and the investigation are created here)**, then 97.0, 98.8, 99.3 and 99.8 as the later steps arrive.
The alert exists before the external transfer. These values come from running the chain on this repository's detector with the shipped
model; other seeds, times of day and scenarios give other values.

#### The operating point (how the thresholds were chosen)

`python -m ml.calibrate_scoring` runs the project's eight seeded scenarios (two benign, six malicious) through the real ingestion and
detection pipeline on a temporary database, for **validation seeds** 1000-1011 and a disjoint
set of **test seeds** 2000-2011 (12 each; 96 runs per split: 72 malicious,
24 benign). The clock is pinned to a weekday at 10:30 local time. It then chooses each band's threshold from the
**validation runs only**: the lowest threshold whose false-flag rate on the benign validation runs stays inside that band's budget
(Watch 25%, Elevated 5%, Alert 0%; these budgets are
policy assumptions about analyst capacity, not measurements), which maximises recall within the budget. The test runs are only
scored afterwards. The result is written to `backend/operating_point.json` (read at start-up) and
[reports/calibration/](reports/calibration) (`scoring_calibration.md`, `.json`, `runs.csv`).

Selected thresholds (risk score): **Watch 37, Elevated 37, Alert 37**; anomaly-model corroboration threshold 0.45.
Each band also needs its independent-stage count (none, 2, 3).

| Band | Threshold | Validation: malicious detected | Validation: benign flagged | Test: malicious detected | Test: benign flagged |
|---|---|---|---|---|---|
| Watch | 37 | 67 of 72 (7% missed) | 6 of 24 (25%) | 67 of 72 (7% missed) | 9 of 24 (38%) |
| Elevated | 37 | 35 of 72 (51% missed) | 0 of 24 (0%) | 35 of 72 (51% missed) | 0 of 24 (0%) |
| Alert | 37 | 22 of 72 (69% missed) | 0 of 24 (0%) | 23 of 72 (68% missed) | 0 of 24 (0%) |

Per scenario on the held-out test runs (12 runs each; how many reached each band):

| Scenario | Kind | Runs | Watch | Elevated | Alert |
|---|---|---|---|---|---|
| Benign employee activity | benign | 12 | 0 | 0 | 0 |
| Benign high-volume transfer (lookalike) | benign | 12 | 9 | 0 | 0 |
| Bulk export | malicious | 12 | 12 | 11 | 8 |
| Compromised-account campaign | malicious | 12 | 12 | 12 | 12 |
| Multiple low-severity signals | malicious | 12 | 12 | 0 | 0 |
| Gradual collection and staging | malicious | 12 | 12 | 0 | 0 |
| Removable-media activity | malicious | 12 | 7 | 0 | 0 |
| Suspicious external transfer | malicious | 12 | 12 | 12 | 3 |

**The trade-off, in this project's synthetic runs.** Lowering the Watch threshold catches more malicious runs and flags more benign
ones; `reports/calibration/scoring_calibration.md` tabulates misses and false flags for thresholds 0-100 on validation and test. At
the selected point the Watch band misses 5 of 72 malicious test runs and flags 9 of 24 benign
ones (all of them the benign lookalike for bulk export); Alert misses 49 of 72 and flags 0. 18 of the
23 malicious test runs that reached Alert did so before the target's final scored event.

* Elevated: the budget alone allowed a threshold of 0; it was raised to 37 so the bands stay ordered. For this band the independent-stage requirement, not the score threshold, is what separates benign runs from malicious ones.
* Alert: the budget alone allowed a threshold of 0; it was raised to 37 so the bands stay ordered. For this band the independent-stage requirement, not the score threshold, is what separates benign runs from malicious ones.
* Watch: the false-flag rate on held-out test runs (37.5%) exceeds the budget (25%) that held on validation (25.0%); a budget met on validation does not guarantee it on new seeds.

**Limits of this calibration.** The labels are the scenario generator's own (a scenario is malicious by construction), the benign class
is two scenarios, and the test seeds come from the same generators as the validation seeds, so the test figures are optimistic about
unseen behaviour. The thresholds are an operating point on synthetic runs: they say how this heuristic behaves here, not how likely an
alert is to be a real attack, and nothing here has been validated on real employees or incidents. Re-run the command after changing
rules, weights, the model or the scenarios; the recorded point is not updated automatically.

### Data exposure assessment (`backend/data_exposure.py`)

Reported separately from the score, so a high score never implies that data was lost. Fields: sensitive records
accessed, records exported, records potentially exposed, records tied to external transfers, and whether an external
transfer was **confirmed**. The status is one of:

| Status | Meaning |
|---|---|
| `none` | no sensitive access |
| `suspicious_access` | sensitive or restricted data was accessed in a suspicious context |
| `confirmed_export` | a large export or download succeeded; the data left the application but is not known to have left the bank |
| `confirmed_external_transfer` | an external transfer event is confirmed |

A large export alone is reported as an export, **never** as exfiltration.

## The lab's attack stages, step by step

These are the stages of the offline scenario lab's manual steps (`POST /api/simulation/steps`, `LAB_MODE=true` only, never in
production) and the ones its *Compromised account campaign* scenario draws from. Defaults for the manual steps: attacker address `203.0.113.45` (an
RFC 5737 documentation address), device `SimulatedAttackerToolkit/1.0 (Linux x86_64; synthetic)`, external destination
`files.exfil-sim.example.invalid`. The attacker uses the target's stolen password through the normal login code path.

| # | Step | What the backend records | Why it is suspicious | Stage |
|---|---|---|---|---|
| 1 | Login from unfamiliar IP | `login` from the simulated external address | IP is not in the employee's baseline; weak on its own | Initial Access |
| 2 | Access restricted resources | `resource_access` on HR, payroll, IT admin console, audit, loans; results `success` or `denied` by the real permission check | denied restricted probes and rapid enumeration across departments | Sensitive Resource Access |
| 3 | Large export | `data_export` or `file_download` of the chosen number of records (default 25,000) from the most sensitive resource the account can reach | far above the employee's history | Collection |
| 4 | Failed administrator logins | five `login_failed` events against the admin console | password guessing; `failed_login_burst` and `admin_console_login_failed` | Credential Misuse |
| 5 | Privileged account creation | `administrative_action` creating `svc.backupNN` with write access to every managed resource (only succeeds if the target has IT admin console write access) | a new privileged account is a persistence mechanism | Privilege Escalation, Persistence |
| 6 | Login with the new account | `login` as `svc.backupNN` | new account used within 24 hours; attributed to the employee that created it | Lateral Movement |
| 7 | External data transfer | `external_transfer` to the external destination, status `confirmed` | records leave the organisation | Exfiltration |

The campaign scenario draws which of these stages happen (login always first), their order (account creation always
precedes the login with it; a transfer always follows an export), the export size, the number of failed administrator
logins (3 to 8) and which 3 to 5 resources are probed from the run's seed, so the stored seed replays the same campaign.
Every stage still goes through the real login, permission checks, event pipeline and detection engine, so a stage the
account is not entitled to is denied (a standard employee cannot create accounts, and restricted access is denied by the
backend), and a campaign that never reaches an export or a transfer is scored accordingly. It varies the sequence; it is
still a scripted simulation, not an adaptive attacker.

When a run reaches a critical alert it is normally by the export or the failed administrator logins, **before the external
transfer**, but that depends on the stages drawn. The external transfer is stored as its own `external_transfer` event with
the records counted separately from the earlier export, so the exposure shows `confirmed_export` first and
`confirmed_external_transfer` only after a confirmed transfer.

## How attacks are prevented, contained and what is not prevented

This project is about **detection and response**. It does not claim to stop a real attacker on a real network. The
controls below work inside the application and the simulation.

### Preventive controls that are always on

| Control | What it stops | Where |
|---|---|---|
| Argon2id salted password hashes (`argon2-cffi`; old PBKDF2 hashes are upgraded at login) | stolen database revealing passwords | `backend/security.py` |
| Equal-time check for unknown employee IDs | user enumeration by timing | `auth_service.authenticate` |
| Random session tokens, only an HMAC is stored, 480-minute lifetime, revocation | stolen database revealing live sessions; sessions that never expire | `security.py` |
| Backend decides identity, IP and device | an attacker choosing a different employee ID or IP in a request | `security.get_auth`, `resolve_ip` |
| Role-based access control (`security_admin` vs `employee`) | employees reaching the SOC, simulation or response endpoints | `require_admin` |
| Failed-login throttle per employee ID and per source address; per-route limits (HTTP 429 with `Retry-After`) | online password guessing, scripted abuse of state-changing routes | `rate_limit.py`, `route_limits.py`, `main.login` |
| `APP_ENV=production` start-up checks | running without a strong `SECRET_KEY`, without demo credentials from a secret source, or with a wildcard CORS origin | `config.validate_for_environment` |
| Shared `TRUSTED_FRONTEND_KEY` (constant-time compare) | an outside caller being attributed to a workstation IP | `security.is_trusted_frontend` |
| Per-resource permission checks on every access | reading or exporting data the role is not granted | `event_service.has_access` |
| Self-only profile endpoint | reading another employee's private record | `portal_routes.py` |
| Input validation (Pydantic), integer overflow limits, safe error handling | malformed requests, crashes, stack-trace leaks | `schemas.py`, `main.py` |
| Idempotency keys | replayed requests being counted twice | `record_event` |
| Append-only evidence with SHA-256 | tampering with an investigation unnoticed | `investigation_service.py` |
| Audit log of logins, account creation, response and failed responses | actions without accountability | `write_audit` |

### Detective controls (what raises the alarm)

Hybrid detection: Isolation Forest anomaly score, 18 rules, a per-employee 30-day baseline, correlation of related
events in a 4-hour window, attack-stage classification and a bounded 0-100 heuristic risk score (not a probability). An alert is
raised when the risk band reaches Alert (score at the calibrated threshold with at least three independent stages), which can be
before the last attack step. Unusual-but-innocent behaviour (new IP, late shift, large legitimate job) cannot reach Alert alone
because of the stage gate; it can reach Watch, and the benign high-volume lookalike does so in some runs (see the calibration results).

### Response controls (containment an administrator can run)

Every action changes this application's own records, which it then enforces (see [Scope](#scope-what-is-enforced-and-what-is-not)).
It needs a security-administrator session, a written reason and, for disruptive actions, `confirm: true`.

**What is recorded** (table `containment_actions`, shown in the Response Centre, the investigation page, the audit log and the
evidence export): the alert (`alert_id`) and/or investigation the action concerns (give either; if you give only an
investigation, its alert is recorded), the requested action, the employee, who initiated it (`performed_by`), when
(`created_at`, UTC), the result (`status` `completed`, shown as "Containment completed"), the human-readable `result` and
`effects` (exactly which records changed), `scope` = `simulated_application_state` and `external_systems_contacted` = `[]`.
Failures are audited as `containment_failed` with the same identifiers.

**Safeguards.**
* *Unauthorised:* employees get 403 and unauthenticated callers 401; an employee's attempt is audited as `containment_unauthorized`.
  Administrators cannot contain their own account, and disruptive actions need `confirm: true` (checked in the backend).
* *Repeated:* at most `CONTAINMENT_MAX_PER_MINUTE` (30) requests per administrator per minute, then 429 with `Retry-After`
  (audited as `containment_rate_limited`); the limiter is in memory and per process.
* *Idempotent:* send an `idempotency_key` (8-64 characters of letters, digits, `_`, `-`) and a retry of the same request returns the
  original action with HTTP 200 and `replayed: true` (audited as `containment_replayed`) instead of acting again; reusing a key for a
  different request is 409. The dashboard sends one key per confirmation, so a double click cannot repeat an action. Without a
  key, a request that would change nothing (locking a locked account, revoking when no session is active, blocking a blocked
  address, resolving a resolved investigation) is refused with 409 and creates no duplicate action.

| Action | Effect in this application's records (nothing external) |
|---|---|
| Disable account (`lock_account`) | the account record's status becomes locked and its session rows are revoked; this backend then returns 403 for new logins |
| Revoke sessions (`revoke_sessions`) | the employee's open session rows are marked revoked (409 if none are active) |
| Block IP in this application (`block_ip`) | the address is added to this application's block list; its login code refuses the address and that address's session rows are revoked. No firewall or network device is involved |
| Remove privileges (`remove_privileges`) | write permission rows become read; on an account created during an incident (such as `svc.backupNN`) every permission row is deleted |
| Restrict sensitive access (`restrict_access`) | the employee's confidential and restricted permission rows, or only the chosen resource's, are deleted |
| Isolate system record (`isolate_system`) | the resource is flagged isolated; the permission check denies every employee until it is released |
| Resolve investigation (`resolve_investigation`) | marks the investigation and its alerts resolved with a reason (a later critical alert opens a new one) |
| Restore account, unblock IP, release system | undo the disruptive actions; no confirmation needed |

Security events, investigation evidence and risk assessments are never modified by containment (a test compares table digests
before and after every action type). Backend modules import no network, mail, subprocess or cloud client (also tested), so
containment cannot reach an external service.

### What is deliberately not covered

* **Login throttling, but no MFA or password reset.** After `LOGIN_MAX_FAILURES` (5) failed sign-ins for one employee ID,
  further attempts get HTTP 429 for `LOGIN_LOCKOUT_SECONDS` (300), even with the right password, and the lockout is
  audited. It is in memory (lost on restart, per process) and per account, so an attacker can also lock a victim out for
  a few minutes. Brute force is additionally *detected* by the burst rules.
* Containment only changes this application's own state. A real deployment would need authorised integrations with a firewall,
  identity provider and endpoint agents, plus review of what automated response is acceptable; no such integration exists or
  is configured here, and nothing in this project should be described as protecting a real organisation.
* The model learns from synthetic data; production use would need real baselines, tuning and review of false positives.
* Detection needs events: an attacker who never touches the application produces nothing to analyse.

## Employee Workspace Portal

http://127.0.0.1:8501. Sidebar: Dashboard, HR Records, Payroll, Documents, Employee Directory, My Profile, Logout.
Sign in with an employee ID and password; the backend decides identity and permissions, and the browser cannot choose
an employee ID or source IP.

| Page | What you can do | Backend rule |
|---|---|---|
| Dashboard | name, employee ID, department, role, last login, available resources, recent activity | own data |
| HR Records | search and open records | needs `hr-records` access |
| Payroll | own payslips; payroll register; CSV export | register needs `payroll-records` read, export needs write |
| Documents | list and download permitted documents | per-document resource permission |
| Employee Directory | search by name, role or department | all employees |
| My Profile | personal and employment information | own data |

Every meaningful action is stored as a security event with: event ID, employee ID, session ID, UTC timestamp, event type
(`login`, `login_failed`, `logout`, `resource_access`, `file_download`, `data_export`, `directory_search`,
`administrative_action`, `external_transfer`, `permission_change_attempt`), resource, source IP, device, outcome
(`success`, `failure`, `denied`), records accessed and downloaded, metadata, and the synthetic flag.

The portal shows no risk scores, alerts or investigations.

## SOC dashboard

http://127.0.0.1:8503, administrators only (employees are refused at sign-in and by every `/api/soc/*` endpoint). Every
figure comes from the backend. Live panels check a small change token every `SOC_REFRESH_SECONDS` (3 s by default) and only reload
when something changed, so filters and navigation are kept. Overview totals cover the last `DASHBOARD_WINDOW_DAYS` days.

| Page | Content |
|---|---|
| Security Overview | KPIs (security events, active investigations, active alerts, employees in the Elevated or Alert band, sensitive records accessed, confirmed external transfers), a "How to read the scores" panel, a live risk meter (heuristic risk score, risk band, impact severity and evidence strength shown separately), active threats |
| Live Event Feed | events with anomaly score (0-1), rule weight points and stage; filters for employee, IP, event type, risk band, time range |
| Attack Investigations | list; selecting one opens the investigation (findings, case file, containment, export, resolve) |
| Employee Risk Monitor | employees ranked by behavioural and rule evidence only (no names or demographics) |
| Attack Timeline | the eight stages built from correlated events, current stage highlighted |
| Attack Graph | accounts, IPs, sessions, systems, privileged accounts and external destinations from stored events |
| Response Centre | recommended containment ("Run containment"), active controls, history with results, manual response |
| Audit Logs | alerts, investigation updates, containment, administrator actions, failed responses |

The risk monitor deliberately ranks only by activity evidence; names, demographics or other personal traits are never
used as risk indicators.

## Investigation and incident response

An Alert-band alert creates one investigation per employee, and every later related event updates it.

* **Case file:** sessions, suspicious IPs, related privileged accounts, first and latest suspicious event, heuristic risk score,
  risk band, impact severity, evidence strength, stage, sensitive resources accessed, records exported, potentially exposed and confirmed external transfers.
* **Status:** `open`, `contained` or `resolved`.
* **Preserved evidence:** related events are collected by employee, session, IP, created account, resource and time and
  copied once into the append-only `investigation_evidence` table with a SHA-256 of the original. Nothing edits events;
  the evidence view and every export compare each copy with the live event (`verified`, `modified`, `missing`).
* **Explanation** (`investigation_explainer.py`, engine `deterministic-evidence-v1`): deterministic, no LLM or network
  call. It gives the likely attack type, stage, suspicious activities, supporting evidence, the risk assessment (score, band, impact severity, evidence strength and the full score breakdown),
  recommended containment, missing evidence and alternative explanations, citing real event IDs and timestamps, and
  never names the person behind an account. The application works with no external API.
* **Classification:** possible insider misuse, compromised credentials, automated account exploitation, privilege
  escalation, unauthorised data export and confirmed external transfer, each reported as supported or not by the evidence.
* **Containment:** see the response table above.
* **Evidence export:** `GET /api/investigations/{id}/export?format=json|csv` returns the incident summary, attack
  timeline, correlated events, risk-score history, data exposure, containment actions and findings for that
  investigation only.

## API

Interactive documentation: `/docs`. Send `Authorization: Bearer <token>` with the token from `POST /api/auth/login`.
"Admin" means the `security_admin` role. Unauthenticated calls return 401, wrong role 403, invalid input 422 or another
4xx; the server does not return stack traces.

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/health` | public | liveness plus a database check (503 `{"status":"unavailable"}` when the database cannot be reached) |
| GET | `/api/system/database` | admin | redacted database URL, dialect, schema version and row counts |
| POST | `/api/auth/login` | public | body `employee_id` + `password` |
| POST | `/api/auth/logout` | any | revoke the session |
| GET | `/api/employees/me`; `/api/employees/{id}` | any; self or admin | profile and permissions |
| GET | `/api/employees` | admin | directory |
| GET / POST | `/api/resources`; `/api/resources/{id}/access` | any | catalogue; view, download or export (403 if not permitted) |
| GET | `/api/portal/profile`, `/payslips`, `/payslips/{period}` | any | own data |
| GET / POST | `/api/portal/payroll/register`, `/payroll/export` | payroll access | register, CSV export |
| GET | `/api/portal/hr/records[/{employee_id}]` | HR access | search, open record |
| GET | `/api/portal/documents[/{id}/download]`, `/directory`, `/directory/departments` | per resource / any | documents, directory |
| POST | `/api/admin/accounts` | IT admin console write | create a privileged account |
| POST / GET | `/api/events`; `/api/events/me` | any | events for the caller only (identity, IP, device set by the backend); an `Idempotency-Key` header (or `request_id`) makes a retry store the event once |
| GET | `/api/events` | admin | history with filters |
| GET / POST | `/api/risk/employees[/{id}]`, `/api/risk/assess` | admin | heuristic `risk_score` (0-100, not a probability), `level` (the **risk band**: `normal`, `suspicious`, `high_risk`, `critical` = Normal, Watch, Elevated, Alert), `impact_severity`, `evidence_strength`, factors with event references, stages, exposure, and `score_breakdown` (formula, components, rule evidence, model output, feature deviations, gate, thresholds) |
| GET / PATCH | `/api/alerts[/{id}]` | admin | alerts with `risk_band`, `impact_severity`, `evidence_strength`, `peak_risk_score` and `score_basis`; filter with `risk_band` and `impact_severity` (there is deliberately no single "severity" field) |
| GET / POST / PATCH | `/api/investigations[/{id}]` | admin | investigations (PATCH only reopens a resolved one) |
| GET | `/api/investigations/{id}/explanation`, `/evidence`, `/export` | admin | explanation, preserved evidence, report download |
| POST | `/api/investigations/{id}/resolve` | admin | `reason` + `confirm: true` |
| GET / POST | `/api/containment` | admin (POST: containment guard) | actions: `revoke_sessions`, `lock_account`, `restrict_access`, `remove_privileges`, `block_ip`, `isolate_system`, `restore_account`, `unblock_ip`, `release_system`, `resolve_investigation`; body takes `employee_id`, `action_type`, `reason`, `investigation_id`, `alert_id`, `target`, `confirm`, `idempotency_key`; 201 on a new action, 200 with `replayed: true` on a retry, 409 for a no-op or key clash, 429 when rate limited |
| GET | `/api/soc/version`, `/overview`, `/risk-history`, `/events`, `/employees`, `/investigations[/{id}]`, `/scopes`, `/timeline`, `/graph`, `/response`, `/audit` | admin | SOC read models; `/events` takes `limit` (capped by `MAX_PAGE_SIZE`) and `before_id` for keyset paging, `/investigations` takes `limit` |
| GET | `/api/dashboard/stats`, `/api/audit-logs` | admin | KPIs, audit trail |
| GET / POST | `/api/detection/status`, `/reload`, `/retrain` | admin | model, thresholds, rules |
| GET / POST | `/api/simulation/scenarios`, `/status`, `/steps`, `/reset` | admin, simulation enabled | scenario catalogue (with per-employee eligibility), simulation state, manual single steps, reset (409 while a run is active) |
| POST / GET | `/api/simulation/runs`, `/runs/{id}`, `POST /runs/{id}/cancel` | admin, simulation enabled | start a seeded scenario run (202; `scenario`, optional `target_employee_id`, `seed`, `records`, `source_ip`, `noise`, `pace`, `idempotency_key`), poll its status, plan, results and observed outcome, stop it; 409 if a run is active or the employee's earlier evidence would be mixed in |

Timestamps are stored in UTC and returned as `timestamp` (UTC) and `timestamp_local`.

### Database tables

| Table | Purpose |
|---|---|
| `employees` | identity, department, role, status (`active`/`locked`), password hash, known IPs, synthetic flag, creator of privileged accounts |
| `employee_sessions` | token hash, IP, device, created, expires, revoked, synthetic flag |
| `access_permissions` | employee, resource, `read` or `write` |
| `security_events` | one row per action: employee, session, UTC time, type, resource, outcome, IP, device, records accessed and downloaded, details JSON, `request_id`, synthetic flag, scenario |
| `risk_assessments` | per-event assessment: heuristic risk score, risk band (`level`), impact severity, evidence strength, anomaly score, stage, rule-evidence factors, score components |
| `security_alerts` | alerts (risk band `severity` column; API field `risk_band`) with impact severity, evidence strength, peak heuristic risk score, the score basis when raised, evidence, exposure, first and triggering event, recommended actions |
| `attack_investigations` | case file and status linked to the alert |
| `investigation_evidence` | append-only evidence copies with SHA-256 hashes |
| `containment_actions` | action: type, alert and investigation, employee, reason, initiating administrator, time, status, result and effects (in `details`), idempotency key |
| `response_controls` | the active blocks, isolations and restrictions the enforcement points consult |
| `audit_logs` | actor, action, target, IP, details, time |
| `simulation_runs` | one row per scenario run: scenario, seed and seed mode, status, parameters, full plan and its SHA-256, per-action results, progress, error, timestamps; events and investigations reference it through `simulation_run_id` |

All tables have timestamps and indexes chosen from the actual queries; the full list of indexes, constraints and
de-duplication rules is in [Database and persistence](#constraints-and-indexes). A separate `schema_migrations` table records
the schema version.

## Project structure

```
app.py                       launcher (loads .env, starts backend and dashboards)
backend/                     FastAPI app, models, detection, correlation, investigation, response, SOC read models
  database.py                engine and connection settings for SQLite and PostgreSQL
  migrations.py              versioned schema migrations (indexes, constraints, de-duplication key)
  db_tools.py                `python -m backend.db_tools copy | upgrade | info`
  detection_rules.json       configurable rules, weights and parameters (all hand-assigned heuristics)
  scoring.py                 the definitions: risk score formula, risk band gate, impact severity, evidence strength
  operating_point.json       the recorded risk-band thresholds (written by ml/calibrate_scoring.py)
data/                        demo_accounts.py (usernames; random passwords come from a git-ignored file or the secret manager), seed_data.py (history), the SQLite file (git-ignored)
deploy/                      single-container deployment: start.py, gateway.py, preflight.py, verify.py, make_secrets.py
ml/                          features.py, synthetic_data.py, train_model.py, anomaly_detector.py, evaluate_dataset.py, calibrate_scoring.py, artifacts/ (git-ignored)
ml/cert/                     CERT r4.2 pipeline: schema, validate, prepare, labels, split, leakage, synthetic supplement
ml/detect/                   window builder, features, models, hybrid risk, benchmark and summary (offline benchmark)
docs/                        cert-dataset.md, detection-evaluation.md, deployment.md, detection-results/
docs/cert-dataset.md         CERT dataset setup, field mapping, label rules, caveats
frontend/                    employee_portal.py, soc_dashboard.py, soc_auth_defense.py, components, theme, api_client
tests/                       567 pytest tests
.streamlit/config.toml       Streamlit theme and server settings
requirements.txt  requirements-dev.txt (adds pgserver for the PostgreSQL tests)  requirements-deploy.txt (pinned runtime for the image)
Dockerfile  .dockerignore  render.yaml  .env.example
```

## Tests

```powershell
python -m pytest tests -q          # 567 tests, about six to twelve minutes (a real backend is started several times)
python -m pip install -r requirements-dev.txt   # optional: adds pgserver so tests/test_postgres.py runs instead of skipping
```

The suite pins its clock: when it starts during business hours the application's clock is moved forward to 21:00 local time
(`tests/conftest.py`), because the attack-chain tests assume the attacker acts after hours and otherwise pass or fail
depending on the time of day.

The suite uses a temporary database and a separate backend process, and an autouse fixture resets the simulation and
removes rows each test creates. It covers:

* **Integration:** a normal employee's session is recorded and scored low; a compromised account (unfamiliar IP, restricted
  payroll access, an 8,000-record export, failed administrator logins, IT portal probe, privileged account and login,
  external transfer) is detected with a rising heuristic risk score, correlated, alerted **before the external transfer**, shown on
  the timeline and graph, investigated, and contained; a new-IP login to a permitted resource is **not** critical.
* **Security and reliability:** hashed passwords and session tokens; every endpoint requires authentication except health
  and login; admin endpoints reject employees; employees cannot read other employees' restricted records; invalid
  paths, queries and bodies never produce a 5xx; audit entries; UTC timestamps; bounded scores whose bands follow the thresholds and the stage gate.
* **Runtime:** data, sessions and the model survive a backend restart; the two Streamlit apps run against a live backend,
  employees are refused by the SOC dashboard, and the apps stay usable when the backend is unreachable.
* **Detection, ML, SOC and investigation workflow:** normal activity, unfamiliar IP, restricted access, large export,
  failed logins, privileged account creation, external transfer, a complete attack, duplicate events, false positives,
  evidence preservation and tamper detection, containment enforcement and report export.
* **Security** (`tests/test_security_hardening.py`, with `test_security.py`): no published default password or secret
  remains in the working tree; local secret and credential files are git-ignored and untracked; Argon2id with legacy-hash
  upgrade and no plaintext in the database file; start-up refusal in production without a secret, CORS origins or demo
  credentials; per-account and per-address brute-force lockout and per-route rate limits with `Retry-After`; role
  escalation, tampered, expired, revoked and locked sessions; oversized, malformed and mistyped payloads without echoing
  input; generic 500s with no paths or stack traces; CORS, security headers, HTTPS requirement and no cookies.
* **Scores and explanations** (`tests/test_scoring.py`): score range and monotonicity; the score is exactly its two components;
  missing evidence (no events, no flagged events, no trained model); duplicate evidence counted once and repeats capped; impact
  severity derived from evidence alone and reported apart from the score band and the evidence strength; one assessment explained
  consistently by the risk API, the SOC investigation audit, the stored explanation, the alert and the export; thresholds chosen
  from validation runs only (changing the test runs cannot move them) and within their false-flag budget; the recorded operating
  point is the one in force and the one the README quotes; the old columns migrate with their values; and no backend or dashboard
  text calls a heuristic a "confidence" or a probability.
* **Persistence and multi-client behaviour** (`tests/test_persistence.py`, `tests/test_postgres.py`): see
  [what was and was not verified](#what-was-and-was-not-verified) for the list; the PostgreSQL file needs `pgserver`.
* **Simulated containment** (`tests/test_containment_simulation.py`): each action records the alert and investigation, the
  initiator, time and result; only this application's tables change (digest comparison before and after every action) and
  evidence tables never do; socket, DNS, SMTP, HTTP and subprocess calls fail the test if attempted, and the backend imports no
  such clients; idempotent retries, key clashes, no-op refusals, rate limiting and audited unauthorised requests; labels,
  notices and the README are scanned for claims of real enforcement.
* **Scenario generator and runs** (`tests/test_simulation_runs.py`): same seed gives the same plan, different seeds vary
  timing, volume, order and noise; ordering constraints hold; only documentation addresses and `.invalid` destinations;
  every scenario runs and stores its seed, plan and status; benign scenarios never alert; malicious scenarios leave their
  expected evidence while their outcome level varies and is decided by the detector; one active run, idempotent
  submissions, stop, failure and restart recovery; runs do not share investigations; no network operation is attempted.

## Security notes and limitations

This is an **educational security-monitoring demo on synthetic data. It is not production banking security** and has not
been reviewed or penetration-tested. What is in place, and what is not:

**In place (all enforced by the backend, never only by hiding UI):**
* **Secrets.** No secret or password is in the source. `SECRET_KEY` has no default: development creates a random per-machine
  key; production refuses to start without one (32+ random characters) from the environment or a secret manager, and
  without `DEMO_PASSWORDS_JSON` (or `AUTO_SEED=false`). Demo passwords are random, per machine, and git-ignored.
* **Passwords.** Argon2id (`argon2-cffi`); legacy hashes verify once and are upgraded at login; plaintext is never stored,
  logged or returned. Session tokens are random and only an HMAC of them is stored.
* **Authentication and authorization.** Every route except `/api/health` and login needs a valid session; administrator
  routes check the role server-side. State-changing routes (simulation, investigations, alerts, containment, detection)
  need the administrator role, and the lab API also needs `LAB_MODE=true` (never in production). Employees can reach only their own data;
  a job title such as IT administrator never grants the SOC role. Expired, revoked, locked and tampered sessions are refused.
* **Brute force and abuse.** Failed sign-ins are throttled per employee ID and per source address (HTTP 429, `Retry-After`);
  uniform error text for unknown IDs and wrong passwords; per-caller, per-minute limits on administrator state changes,
  expensive actions and employee actions; a separate limit and audit trail for containment.
* **Requests.** Pydantic validates types, lengths and ranges; bodies over `MAX_REQUEST_BYTES` get 413; validation errors
  return only the field, a short message and the error type (never the submitted value); unexpected errors return a
  generic 500 with a request id and the stack trace stays in the server log; API responses name files, not server paths.
* **CORS and headers.** Explicit origins only (a wildcard stops start-up), no credentials, named methods and headers.
  Every response carries `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` and a
  deny-all CSP; `Strict-Transport-Security` is sent when the request arrived over HTTPS.
* **Sessions and cookies.** The backend sets **no cookies**: sessions are bearer tokens in the `Authorization` header, held
  in each Streamlit session's server-side state, so classic CSRF does not apply to the API. Streamlit's own XSRF and
  origin checks stay enabled (`.streamlit/config.toml`).
* **HTTPS.** **The application does not provide HTTPS.** Run it behind a TLS-terminating host or proxy. With
  `REQUIRE_HTTPS` (on by default in production) plain-HTTP requests are refused except from loopback and `/api/health`;
  behind a proxy you control set `TRUST_FORWARDED_PROTO=true`. Without a proxy, tokens and passwords travel in clear text.
* **Docs.** `/docs`, `/redoc` and `/openapi.json` are off in production unless `ENABLE_API_DOCS=true`.

**Not in place / known limitations:**
* No MFA, password reset, password-strength policy for self-chosen passwords beyond length, or account-recovery flow.
* Rate limits and lockouts are in memory and per process (lost on restart, not shared between workers); a lockout can also
  be used to lock a victim out for a few minutes. Use one worker, or add a shared store and a gateway/WAF for real use.
* Sessions are valid for `SESSION_TTL_MINUTES` (480) with no idle timeout, and revoked only by logout or containment.
* Source-IP attribution relies on the loopback mapping or `TRUSTED_FRONTEND_KEY`; anyone holding that key can have a
  request attributed to a workstation address. Keep it secret and rotate it.
* SQLite has no encryption at rest, role separation or backup, and PostgreSQL's protections (TLS to the database, access
  control, backups, encryption at rest) are whatever your provider and your configuration give you; the local secret and
  credential files are protected only by file permissions. Anyone with the host can read them.
* Passwords committed to earlier versions of this repository remain in its git history (a start-up sync replaces them in
  an existing database, but they must be considered public). There is no dependency or container scanning here.
* Audit logs are database rows an administrator with database access could alter; they are not tamper-evident.

## Known limitations

* **Local demonstration only.** It is not hardened for production (see [Security notes](#security-notes-and-limitations)): no
  TLS of its own, no MFA, no password reset. Treat the demo accounts as exposed to anyone who can reach the dashboards.
* **Synthetic data.** The model is trained on generated sessions; its metrics, the rule weights and the two score weights
  (0.80 rules, 0.20 anomaly) are hand-assigned for the case study and would need real data and tuning before any real use; they are
  not learned from labelled outcomes. The risk-band thresholds were chosen on synthetic validation runs only
  ([the operating point](#the-operating-point-how-the-thresholds-were-chosen)); the risk score is a ranking heuristic, never a probability.
* **The volume guard was tuned against the synthetic attacks** (see Machine learning), so its recall is in-sample.
* **Detection quality is modest and mostly measured on synthetic data.** On the held-out CERT r4.2 users the best unsupervised
  detector has F1 about 0.2 at a 0.3 % window false-positive rate, and the supervised reference shows what labels would add. The
  benchmark's early-warning evidence covers only incidents that span many days. See docs/detection-evaluation.md.
* **Containment is application-level.** Blocking, isolating, locking and privilege removal change this application's records,
  which it enforces itself; there is no firewall, directory, email or endpoint integration, and the Response Centre says so.
  An address block does not stop traffic reaching the host, only this application's own login.
* **Source IPs:** the backend trusts only the TCP peer. On one machine every client is loopback, so
  `MAP_LOOPBACK_TO_WORKSTATION` attributes it to the employee's registered workstation IP; with split hosting the
  shared `TRUSTED_FRONTEND_KEY` does the same for requests from your own dashboards. `X-Forwarded-For` is ignored. Anyone
  holding the key can have their request attributed to a workstation IP, so keep it secret.
* **SQLite, polling and single-process state.** SQLite is a single-writer, single-host development store and is not
  production-scale; production refuses it by default. PostgreSQL support is tested only against an embedded PostgreSQL 16.2
  (see [what was and was not verified](#what-was-and-was-not-verified)). The baseline cache, the detector, the rate limiters
  and the simulation runner live in one process's memory, so run a single backend worker even with PostgreSQL. Dashboards poll
  a change token (default every 3 s) and each open SOC session costs one small request per interval; there is no push channel.
  Two simultaneous critical events for one employee are now serialised and backed by unique indexes, but this was exercised
  with a handful of parallel requests, not under load.
* **One active investigation per employee.** Once resolved, a later Alert-band alert opens a new one.
* **Explanations are rule-based.** They state only what the stored events show; an LLM is not used.
* **Evidence retention.** Nothing deletes real events, but the lab's reset deletes synthetic events and investigations,
  by design (it exists only in development and test setups).
* **Genuine activity during a run** is scored in the same correlation window as the simulated attack.
* **Scenario runs are scripted, bounded generators, not adaptive attackers.** Randomisation changes timing, volumes, ordering
  and background noise within fixed rules; it does not react to detections (apart from actions being blocked by containment).
  Runs execute on a thread inside the backend process (one at a time), so they do not survive a restart (they are marked
  failed) and need a single backend worker. The runner calls the backend's ingestion functions in-process rather than over
  HTTP, which is the same persistence and detection path the API routes use but not the HTTP layer itself. The removable-media
  rule is new and has not been evaluated on the CERT benchmark.
* **Tables are static HTML** (no client-side sorting or export); charts are Plotly.
* Times use `DISPLAY_TIMEZONE` (default `Asia/Kolkata`); business hours are 07:00-19:00 in that zone.
