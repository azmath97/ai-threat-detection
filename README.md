# AI-Based Insider Threat Detection System

A cybersecurity case study. A fictional financial organisation, **Westbridge Bank**, runs an Employee Workspace
Portal. A security team watches it through a Security Operations Centre (SOC) dashboard. An employee account can be
compromised or misused, and the system must notice that **while it is happening** and before data leaves the bank.

* **All data is synthetic.** There are no real credentials, personal data or banking data anywhere in the project.
* **One FastAPI backend and one SQLite database are the single source of truth.** The portal, the SOC dashboard and
  the simulation console only call the backend; none of them has its own data, scores or event system.
* **Detection is hybrid:** an Isolation Forest anomaly model, configurable rules, event correlation, a bounded
  0-100 attack-confidence score, a separate data-exposure assessment and attack-stage classification.
* **Containment is real inside the simulation:** disabling an account stops logins, blocking an IP stops sessions from
  it, removing privileges removes permissions. It never touches a real network.

## Contents

1. [Architecture](#architecture) · 2. [Technology stack](#technology-stack) · 3. [Install and run](#install-and-run)
· 4. [Environment setup](#environment-setup) · 5. [Database initialisation](#database-initialisation)
· 6. [Demo credentials](#demo-credentials) · 7. [Launching](#launching-the-application)
· 8. [Simulate an attack](#how-to-simulate-an-attack) · 9. [Reset the simulation](#how-to-reset-the-simulation)
· 10. [Employee Portal](#employee-workspace-portal) · 11. [SOC dashboard](#soc-dashboard)
· 12. [Detection engine](#detection-engine) · 13. [Investigation and response](#investigation-and-incident-response)
· 14. [API](#api) · 15. [Tests](#tests) · 16. [Known limitations](#known-limitations)

## Architecture

```
 Employee Portal  (Streamlit :8501) --\
 Simulation Console (Streamlit :8502) ---HTTP/JSON-->  FastAPI backend (:8000)  -->  SQLite  data/insider_threat.db
 SOC Dashboard    (Streamlit :8503) --/                      |
                                                            +-- ml/  Isolation Forest (ml/artifacts/*.joblib)
 every action -> security event -> rules -> ML score -> correlation -> confidence -> alert -> investigation
```

**Event pipeline** (`backend/event_service.py`). Every employee action is turned into a `security_events` row by the
backend, then flows through the same steps for real employees and for the simulation:

1. persist the event (identity, session, IP and device come from the authenticated session, never from the client);
2. apply the configurable rules against the employee's role, permissions, 30-day baseline and session context;
3. score the behaviour with the Isolation Forest (or the heuristic fallback);
4. correlate related events (same employee, session, unfamiliar IP, or an account created by that employee);
5. compute the bounded attack confidence, the attack stage and the data exposure;
6. at the **critical** threshold raise an alert and create/update an investigation with preserved evidence.

The dashboards only read what the backend stored. The portal never shows scores, alerts or investigations.

| Area | Files |
|---|---|
| API and auth | `backend/main.py`, `auth_service.py`, `security.py`, `portal_routes.py`, `schemas.py` |
| Database | `backend/models.py`, `database.py`, `data/seed_data.py` (9 tables plus `response_controls` and `investigation_evidence`) |
| Detection | `detection_engine.py`, `detection_rules.json`, `rules.py`, `baseline.py`, `correlation_engine.py`, `threat_engine.py`, `data_exposure.py`, `ml/` |
| Investigation and response | `investigation_service.py`, `investigation_explainer.py`, `investigation_export.py`, `investigation_routes.py`, `response_service.py`, `controls.py` |
| SOC read models | `soc_service.py`, `soc_routes.py` |
| Simulation | `simulation_service.py`, `simulation_routes.py` |
| Front ends | `frontend/employee_portal.py`, `soc_dashboard.py`, `simulation_console.py`, `components.py`, `soc_components.py`, `api_client.py` |
| Tests | `tests/` (134 tests) |

## Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, Uvicorn, Pydantic 2 |
| Database | SQLite through SQLAlchemy 2 (timestamps stored in UTC, shown in `DISPLAY_TIMEZONE`) |
| Machine learning | scikit-learn `IsolationForest`, NumPy, joblib (model saved locally and reused) |
| Dashboards | Streamlit and Plotly (charts and the attack graph); custom CSS theme in `frontend/theme.py` (responsive down to phone width, no external fonts or assets) |
| Security | PBKDF2-SHA256 salted password hashes, random session tokens stored as HMAC digests |
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
python app.py all
```

macOS / Linux:

```bash
git clone https://github.com/azmath97/ai-threat-detection.git && cd ai-threat-detection
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py all
```

That starts the backend and all three dashboards:

| Service | URL |
|---|---|
| Backend API and interactive docs | http://127.0.0.1:8000 and http://127.0.0.1:8000/docs |
| Employee Workspace Portal | http://127.0.0.1:8501 |
| Simulation Console (administrators) | http://127.0.0.1:8502 |
| SOC Dashboard (administrators) | http://127.0.0.1:8503 |

On first start the backend creates and seeds the database and trains the anomaly model (a few seconds). If port 8000
is already used, set `API_PORT` first: `$env:API_PORT="8010"; python app.py all` (bash: `API_PORT=8010 python app.py all`).
The dashboards are told where the backend is automatically.

## Environment setup

Everything works with defaults and no `.env` file. To change settings, copy `.env.example` to `.env`:

```powershell
Copy-Item .env.example .env        # bash: cp .env.example .env
```

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./data/insider_threat.db` | database location |
| `SECRET_KEY` | demo value | keys the session-token HMAC; **change it for anything but a local demo** |
| `SESSION_TTL_MINUTES` | `480` | session lifetime |
| `DISPLAY_TIMEZONE` | `Asia/Kolkata` | zone used for `*_local` timestamps and "after hours" |
| `CORS_ORIGINS` | portal and SOC origins | allowed browser origins |
| `AUTO_SEED` | `true` | seed the synthetic data when the database is empty |
| `SIMULATION_ENABLED` | `true` | set `false` for "normal" mode; the simulation API then returns 403 to everyone |
| `MAP_LOOPBACK_TO_WORKSTATION` | `true` | local demo: attribute loopback connections to the employee's registered workstation IP |
| `API_HOST`, `API_PORT`, `API_BASE_URL` | `127.0.0.1`, `8000`, `http://127.0.0.1:8000` | where the backend listens and where dashboards find it |
| `CORRELATION_WINDOW_MINUTES` | `240` | correlation window |
| `THREAT_SUSPICIOUS_THRESHOLD`, `THREAT_HIGH_THRESHOLD`, `THREAT_CRITICAL_THRESHOLD` | `25`, `50`, `80` | severity bands |
| `ALERT_MIN_SEVERITY` | `critical` | lowest severity that raises an alert |
| `ML_MODEL_PATH`, `ML_AUTO_TRAIN` | `ml/artifacts/isolation_forest.joblib`, `true` | model file and train-on-first-start |

Rule severities, scoring weights and parameters live in `backend/detection_rules.json` (reload with
`POST /api/detection/reload`).

## Database initialisation

Nothing to run manually: the backend creates all tables and seeds the data on first start (`AUTO_SEED=true`), and
adds columns missing from databases created by earlier versions. To rebuild from scratch:

```powershell
python -m data.seed_data --reset     # drops and re-creates the demo database
python -m ml.train_model --export    # optional: retrain the model; --export also writes ml/artifacts/*.csv
```

Seeded data: 10 employees in Finance, HR, IT, Trading, Customer Service, Compliance, Engineering, Lending and Marketing
plus a security administrator; different roles and permissions; 14 days of normal activity including historical logins,
known workstation IPs, occasional unfamiliar travel/home IPs and a few after-hours sessions. Data persists across
restarts (SQLite file).

## Demo credentials

For local demonstration only; every account is synthetic and has its own password. Sign in with the **Employee ID**
(the username also works). Emails are `<username>@westbridgebank.test`. The passwords live in `data/demo_accounts.py` and
are stored in the database only as salted PBKDF2-SHA256 hashes.

| Employee ID | Name | Department / job role | Password | Access (resource: level) | Registered IP(s) |
|---|---|---|---|---|---|
| `EMP-1001` | Alice Morgan | Finance / Financial Analyst | `Cedar#Harbor47` | Financial Reports rw, Customer Accounts r, Wiki r | 10.20.1.11, 10.20.1.12 |
| `EMP-1002` | Bob Chen | Finance / Payroll Specialist | `Quill&Meadow82` | Payroll Records rw, Financial Reports r, Wiki r | 10.20.1.21 |
| `EMP-1003` | Carol Diaz | HR / HR Manager | `Birch!Lantern26` | HR Records rw, Payroll Records r, Wiki r | 10.20.2.31, 10.20.2.32 |
| `EMP-1004` | David Kumar | IT / Systems Administrator | `Falcon$Ridge63` | IT Admin Console rw, Source Code r, Wiki rw | 10.20.3.41 |
| `EMP-1005` | Emma Wilson | Trading / Risk Analyst | `Willow#Summit19` | Trading Reports rw, Financial Reports r, Wiki r | 10.20.4.51 |
| `EMP-1006` | Frank Osei | Customer Service / Account Manager | `Amber%Compass74` | Customer Accounts rw, Wiki r | 10.20.5.61, 10.20.5.62 |
| `EMP-1007` | Grace Lee | Compliance / Compliance Officer | `Juniper!Atlas58` | Audit Reports rw, Financial Reports r, Customer Accounts r, Wiki r | 10.20.6.71 |
| `EMP-1008` | Henry Novak | Engineering / Software Engineer | `Granite#Voyage31` | Source Code rw, Wiki rw | 10.20.7.81 |
| `EMP-1009` | Isla Murphy | Lending / Loan Officer | `Coral&Beacon95` | Loan Applications rw, Customer Accounts r, Wiki r | 10.20.8.91 |
| `EMP-1010` | Jack Silva | Marketing / Marketing Coordinator | `Cobalt!Meadow68` | Marketing Assets rw, Wiki r | 10.20.9.101 |
| `SEC-9011` | Sam Okafor | Security / SOC Analyst (**security administrator**) | `Sentinel#Vault2026` | Audit Reports r, Wiki r; SOC dashboard and simulation console | 10.20.10.5 |

Every employee can also reach the self-service pages (own profile and payslips, directory, document library). The HR
manager sees HR records, the payroll specialist the payroll register and export, and the IT administrator can create
privileged accounts; the security administrator is the only role that can open the SOC dashboard or the simulation.

## Launching the application

```powershell
python app.py all           # backend + portal + simulation console + SOC dashboard
python app.py               # backend only
python app.py portal        # one dashboard (needs the backend running): portal | simulation | soc
```

Stop with Ctrl+C. All state stays in `data/insider_threat.db`.

## How to simulate an attack

The simulation runs through the **same** authentication, permission checks, event collection and detection engine as a
normal employee. It is only available to the security administrator and clearly marked as synthetic.

**With the dashboards** (best for a demo)

1. Open the SOC Dashboard (http://127.0.0.1:8503), sign in as `SEC-9011` and stay on *Security Overview*.
2. Open the Simulation Console (http://127.0.0.1:8502), sign in as `SEC-9011`.
3. Choose the scenario and account (default: `EMP-1004`), the attacker's source IP and the number of records, then press
   **Run complete scenario**, or run the steps one at a time.
4. Watch the SOC dashboard: the confidence meter rises, a **Critical** alert and an investigation appear, and the
   timeline, graph and Response Centre fill in. The alert comes at the large-export step, before the external transfer.

**With the API**

```powershell
$base = "http://127.0.0.1:8000"
$login = '{"employee_id":"SEC-9011","password":"Sentinel#Vault2026"}'
$tok = (Invoke-RestMethod "$base/api/auth/login" -Method Post -ContentType application/json -Body $login).access_token
$h = @{ Authorization = "Bearer $tok" }
$employees = Invoke-RestMethod "$base/api/employees" -Headers $h
$david = ($employees | Where-Object username -eq "david.kumar").id
$body = @{ target_employee_id = $david; source_ip = "185.220.101.45"; records = 8000 } | ConvertTo-Json
Invoke-RestMethod "$base/api/simulation/run" -Method Post -Headers $h -ContentType application/json -Body $body
```

The steps are: (1) login from an unfamiliar IP, (2) probe restricted resources (HR, payroll, IT administrator portal,
audit, lending), (3) export `records` records, (4) five failed administrator logins, (5) create a privileged account,
(6) log in with it, (7) transfer the records to an external destination. Run one step with
`POST /api/simulation/steps` (`{"target_employee_id": .., "step": "large_export", "records": 8000}`).
Run it on an account nobody is using: genuine activity during the run is scored in the same window.

## How to reset the simulation

* Simulation Console: tick *Confirm reset*, press **Reset simulation**.
* API: `POST /api/simulation/reset` (administrator).

Reset removes every synthetic event, session, alert, investigation (with its evidence), assessment, privileged account
and response control, undoes containment applied to the affected employees and restores their last-login time. Real
(non-synthetic) data is never touched. The reset is recorded in the audit log.

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

## SOC dashboard

http://127.0.0.1:8503, administrators only (employees are refused at sign-in and by every `/api/soc/*` endpoint). Every
figure comes from the backend. Live panels poll a small change token every 3 seconds and only reload when something
changed, so filters and navigation are kept.

| Page | Content |
|---|---|
| Security Overview | KPIs, live attack-confidence meter, active threats |
| Live Event Feed | events with anomaly score, risk contribution and stage; filters for employee, IP, event type, severity, time range |
| Attack Investigations | list; selecting one opens the investigation (findings, case file, containment, export, resolve) |
| Employee Risk Monitor | employees ranked by behavioural and rule evidence only (no names or demographics) |
| Attack Timeline | the eight stages built from correlated events, current stage highlighted |
| Attack Graph | accounts, IPs, sessions, systems, privileged accounts and external destinations from stored events |
| Response Centre | recommended containment, active controls, history, manual response |
| Audit Logs | alerts, investigation updates, containment, administrator actions, failed responses |

## Detection engine

```
event -> rules -> baseline -> ML anomaly score -> correlation -> attack confidence (0-100) -> data exposure -> stage -> alert
```

| Part | What it does |
|---|---|
| Anomaly detection (`ml/`) | Isolation Forest on 10 behavioural features (login hour, unfamiliar IP, failed logins, resources and departments accessed, download volume, restricted attempts, privilege escalation, external transfer volume, denied accesses). Trained only on **normal** synthetic sessions, saved to `ml/artifacts/`, loaded at start. A heuristic **fallback** on the same features is used if the model is missing or unusable. |
| Rules (`detection_rules.json`) | 18 configurable rules judged against the employee's role, permissions, history and session. An unfamiliar IP or an after-hours login is a weak signal on its own, not an attack. |
| Correlation | Links events by employee, session, unfamiliar IP and related (created) accounts inside a configurable window. Stages come from evidence in any order; each event counts for one stage and repeated evidence is discounted, so nothing is counted twice. |
| Attack confidence | `100 x (0.20 ML + 0.30 rules + 0.25 correlation + 0.10 baseline + 0.15 stage)`. Each component is 0-1 and the weights sum to 1, so the score is bounded. Fewer than 2 independent stages cannot exceed High Risk, fewer than 3 cannot be Critical. The whole-number score is floored so it always matches its severity band. |
| Severity | 0-24 Normal, 25-49 Suspicious, 50-79 High Risk, 80-100 Critical (configurable). |
| Data exposure | Separate from the score: sensitive records accessed, exported, potentially exposed, in external transfers, and whether a transfer was **confirmed**. A large export alone never claims exfiltration. |
| Stages | Initial Access, Credential Misuse, Sensitive Resource Access, Collection, Privilege Escalation, Persistence, Lateral Movement, Exfiltration (needs a confirmed external transfer). |

A new IP address plus access to a permitted resource is recognised (`unfamiliar_ip`) but stays at Suspicious or below.
Duplicate requests (same `request_id` / `Idempotency-Key`) are stored and scored once. On the synthetic held-out set the
model reaches ROC-AUC 0.98 with about 2% false positives on normal sessions; this says nothing about real data.

## Investigation and incident response

A critical alert creates one investigation per employee, and every later related event updates it.

* **Case file:** sessions, suspicious IPs, related privileged accounts, first and latest suspicious event, confidence,
  stage, sensitive resources accessed, records exported, potentially exposed and confirmed external transfers.
* **Preserved evidence:** related events are collected by employee, session, IP, created account, resource and time and
  copied once into the append-only `investigation_evidence` table with a SHA-256 of the original. Nothing edits events;
  the evidence view and every export compare each copy with the live event (`verified`, `modified`, `missing`).
* **Explanation** (`investigation_explainer.py`): deterministic, no LLM or network call. It gives the likely attack type,
  stage, suspicious activities, supporting evidence, confidence, impact, recommended containment, missing evidence and
  alternative explanations, citing real event IDs and timestamps, and never names the person behind an account.
* **Classification:** possible insider misuse, compromised credentials, automated account exploitation, privilege
  escalation, unauthorised data export and confirmed external transfer, each reported as supported or not.
* **Containment** (administrator, `confirm: true`, reason, audited): disable account, revoke sessions, block IP, remove
  privileges, restrict a sensitive resource, isolate a system, resolve the investigation (plus restore, unblock, release).
* **Evidence export:** `GET /api/investigations/{id}/export?format=json|csv` returns only that investigation's evidence.

## API

Interactive documentation: `/docs`. Send `Authorization: Bearer <token>` from `POST /api/auth/login`. "Admin" means the
`security_admin` role. Unauthenticated calls return 401, wrong role 403, invalid input 422/4xx; the server does not return
stack traces.

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/health` | public | liveness |
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
| POST / GET | `/api/events`; `/api/events/me` | any | events for the caller only (identity, IP, device set by the backend) |
| GET | `/api/events` | admin | history with filters |
| GET / POST | `/api/risk/employees[/{id}]`, `/api/risk/assess` | admin | risk, factors, stages, exposure |
| GET / PATCH | `/api/alerts[/{id}]` | admin | alerts |
| GET / POST / PATCH | `/api/investigations[/{id}]` | admin | investigations (PATCH only reopens a resolved one) |
| GET | `/api/investigations/{id}/explanation`, `/evidence`, `/export` | admin | explanation, preserved evidence, report download |
| POST | `/api/investigations/{id}/resolve` | admin | `reason` + `confirm: true` |
| GET / POST | `/api/containment` | admin | `revoke_sessions`, `lock_account`, `restrict_access`, `remove_privileges`, `block_ip`, `isolate_system`, `restore_account`, `unblock_ip`, `release_system`, `resolve_investigation` (`confirm` for disruptive ones) |
| GET | `/api/soc/version`, `/overview`, `/confidence-history`, `/events`, `/employees`, `/investigations[/{id}]`, `/scopes`, `/timeline`, `/graph`, `/response`, `/audit` | admin | SOC read models |
| GET | `/api/dashboard/stats`, `/api/audit-logs` | admin | KPIs, audit trail |
| GET / POST | `/api/detection/status`, `/reload`, `/retrain` | admin | model, thresholds, rules |
| GET / POST | `/api/simulation/scenarios`, `/status`, `/steps`, `/run`, `/reset` | admin, simulation enabled | attack simulation (`records` sets the export size) |

Timestamps are stored in UTC and returned as `timestamp` (UTC) and `timestamp_local`.

## Tests

```powershell
python -m pytest tests -q          # 134 tests, about one minute
```

The suite uses a temporary database and a separate backend process. It covers:

* **Integration:** a normal employee's session is recorded and scored low; a compromised account (unfamiliar IP, restricted
  payroll access, an 8,000-record export, failed administrator logins, IT portal probe, privileged account and login,
  external transfer) is detected with rising confidence, correlated, alerted **before the external transfer**, shown on
  the timeline and graph, investigated, and contained; a new-IP login to a permitted resource is **not** critical.
* **Security and reliability:** hashed passwords and session tokens; every endpoint requires authentication except health
  and login; admin endpoints reject employees; employees cannot read other employees' restricted records; invalid
  paths, queries and bodies never produce a 5xx; audit entries; UTC timestamps; bounded scores that match the severity bands.
* **Runtime:** data, sessions and the model survive a backend restart; the three Streamlit apps run against a live backend,
  employees are refused by the SOC dashboard, and the apps stay usable when the backend is unreachable.
* **Detection, ML, SOC and investigation workflow:** every scenario in the specification, duplicates, false positives,
  evidence preservation and tamper detection, containment enforcement and report export.

## Known limitations

* **Local demonstration only.** It is not hardened for production: HTTP only, no MFA, no password reset, no login rate
  limiting or account throttling, and the default `SECRET_KEY` must be changed.
* **Synthetic data.** The model is trained on generated sessions; its metrics, the rule severities and the scoring weights
  are hand-tuned for the case study and would need real data and tuning before any real use.
* **Simulated containment.** Blocking, isolating, locking and privilege removal change application state only; there is no
  firewall, directory or endpoint integration.
* **Source IPs:** the backend trusts only the TCP peer. On one machine every client is loopback, so
  `MAP_LOOPBACK_TO_WORKSTATION` attributes it to the employee's registered workstation IP; `X-Forwarded-For` is ignored.
* **SQLite and polling.** One local database file and 3-second polling suit a demo, not concurrent multi-site use.
* **One active investigation per employee.** Once resolved, a later critical alert opens a new one.
* **Explanations are rule-based.** They state only what the stored events show; an LLM is not used.
* **Evidence retention.** Nothing deletes real events, but *Reset simulation* deletes synthetic events and investigations,
  by design.
* **Genuine activity during a run** is scored in the same correlation window as the simulated attack.
* **Tables are static HTML** (no client-side sorting or export); charts are Plotly.
* Times use `DISPLAY_TIMEZONE` (default `Asia/Kolkata`); business hours are 07:00-19:00 in that zone.
