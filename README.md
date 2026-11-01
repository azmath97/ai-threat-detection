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

1. [Architecture](#architecture)
2. [Technology stack](#technology-stack)
3. [Install and run](#install-and-run)
4. [Environment setup](#environment-setup)
5. [Database initialisation](#database-initialisation)
6. [Demo credentials](#demo-credentials)
7. [Launching](#launching-the-application)
8. [Simulate an attack](#how-to-simulate-an-attack) and [reset](#how-to-reset-the-simulation)
9. [How it works, end to end](#how-it-works-end-to-end)
10. [The data: what is stored and what datasets are used](#the-data)
11. [Machine learning in detail](#machine-learning-in-detail)
12. [Detection rules in detail](#detection-rules-in-detail)
13. [Baseline, correlation, scoring and data exposure](#baseline-correlation-scoring-and-data-exposure)
14. [The simulated attack, step by step](#the-simulated-attack-step-by-step)
15. [How attacks are prevented, contained and what is not prevented](#how-attacks-are-prevented-contained-and-what-is-not-prevented)
16. [Employee Portal](#employee-workspace-portal) and [SOC dashboard](#soc-dashboard)
17. [Investigation and incident response](#investigation-and-incident-response)
18. [API](#api)
19. [Project structure](#project-structure)
20. [Tests](#tests)
21. [Known limitations](#known-limitations)

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
| Front ends | `frontend/employee_portal.py`, `soc_dashboard.py`, `simulation_console.py`, `components.py`, `soc_components.py`, `theme.py`, `api_client.py` |
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

Everything works with defaults and no `.env` file. To change settings, copy `.env.example` to `.env`
(`app.py` loads it):

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
| `SIMULATION_PRIVILEGED_PASSWORD` | `Synthetic#Priv2026` | password given to the privileged account the simulation creates |
| `MAP_LOOPBACK_TO_WORKSTATION` | `true` | local demo: attribute loopback connections to the employee's registered workstation IP |
| `API_HOST`, `API_PORT`, `API_BASE_URL` | `127.0.0.1`, `8000`, `http://127.0.0.1:8000` | where the backend listens and where dashboards find it |
| `CORRELATION_WINDOW_MINUTES` | `240` | correlation window |
| `BASELINE_DAYS` | `30` | how much history forms an employee's behavioural baseline |
| `BULK_RECORD_THRESHOLD` | `500` | minimum record count that counts as a "large" export |
| `THREAT_SUSPICIOUS_THRESHOLD`, `THREAT_HIGH_THRESHOLD`, `THREAT_CRITICAL_THRESHOLD` | `25`, `50`, `80` | severity bands |
| `ALERT_MIN_SEVERITY` | `critical` | lowest severity that raises an alert |
| `ML_MODEL_PATH`, `ML_AUTO_TRAIN` | `ml/artifacts/isolation_forest.joblib`, `true` | model file and train-on-first-start |

Rule severities, scoring weights and parameters live in `backend/detection_rules.json` (reload with
`POST /api/detection/reload`, no restart needed).

## Database initialisation

Nothing to run manually: the backend creates all tables and seeds the data on first start (`AUTO_SEED=true`), and
adds columns missing from databases created by earlier versions. To rebuild from scratch:

```powershell
python -m data.seed_data --reset     # drops and re-creates the demo database
python -m ml.train_model --export    # optional: retrain the model; --export also writes ml/artifacts/*.csv
```

Data persists across restarts (SQLite file `data/insider_threat.db`, git-ignored).

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
| `SEC-9011` | Sam Okafor | Security / SOC Analyst (**security administrator**) | `Sentinel#Vault2026` | Audit Reports r, Wiki r; SOC dashboard and simulation console | 10.20.10.5 (also 127.0.0.1 and ::1) |

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

Run one step with `POST /api/simulation/steps` (`{"target_employee_id": .., "step": "large_export", "records": 8000}`).
Run it on an account nobody is using: genuine activity during the run is scored in the same window.
The seven steps are explained in [The simulated attack, step by step](#the-simulated-attack-step-by-step).

## How to reset the simulation

* Simulation Console: tick *Confirm reset*, press **Reset simulation**.
* API: `POST /api/simulation/reset` (administrator).

Reset removes every synthetic event, session, alert, investigation (with its evidence), assessment, privileged account
and response control, undoes containment applied to the affected employees and restores their last-login time. Real
(non-synthetic) data is never touched. The reset is recorded in the audit log.

## How it works, end to end

1. **Sign in.** The portal posts the employee ID and password to `POST /api/auth/login`. The backend looks the employee
   up, verifies the PBKDF2 hash (a dummy hash is checked for unknown IDs so timing does not reveal whether an ID exists),
   refuses blocked IPs and locked accounts, opens a session, returns a random token and records a `login` event (or a
   `login_failed` event with the reason: `bad_password`, `ip_blocked`, `account_locked`).
2. **Authenticated requests.** Every later call carries `Authorization: Bearer <token>`. The backend hashes the token
   with HMAC, finds the session, and rejects it if it is unknown, revoked or expired (401), if the account is locked
   (403) or if the caller's IP is blocked (403). The *employee, session, IP and device used for events all come from this
   context*, never from the request body.
3. **Resource access.** For every view, download or export the backend checks the permission table
   (`view`/`download` need `read`, `export` needs `write`; self-service pages are open to every employee; an *isolated*
   system denies everyone). The result (`success` or `denied`) is stored as an event with the number of records involved.
4. **Detection.** Each stored event is run through the pipeline (rules, baseline, ML, correlation, confidence, exposure)
   and gets a risk assessment row. Nothing is scored in the browser.
5. **Alert and investigation.** When the correlated confidence reaches the critical threshold, a `security_alerts` row is
   written (with evidence, exposure and recommended actions) and an investigation is opened or updated.
6. **Response.** An administrator reviews the investigation in the SOC dashboard and applies containment. The backend
   changes the simulated state and writes an audit log; the next login or request from the affected account or IP is
   refused.
7. **Evidence.** The administrator downloads a JSON or CSV report that contains only that investigation's evidence.

### How the three screens stay in sync

The SOC dashboard polls `GET /api/soc/version` every 3 seconds. That endpoint returns a small change token built from the
latest event, assessment and audit IDs and the counts and update times of alerts, investigations, response controls and
employees. The page only reloads its data when the token changes, so filters, selected
investigation and navigation are preserved while new events appear.

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
* Everything created later by the simulation is flagged `is_synthetic = true` (events also carry `"synthetic": true` in
  their metadata) and is removed by *Reset simulation*. Seeded history is also synthetic data, but it is the "real"
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
* **Measured on the held-out synthetic test set (839 windows):**

  | Metric | Value |
  |---|---|
  | ROC-AUC | 0.978 |
  | False positives on all normal windows | 2.4% |
  | False positives on hard normals | 6.4% (unfamiliar IP only 11.7%, heavy plausible download 5.0%, after-hours only 3.3%, legitimate admin work 0%) |
  | Attack recall using the ML score alone | 83.9% |
  | Mean anomaly score | normal 0.027, attack 0.758 |

  Per scenario recall: `brute_force`, `external_transfer`, `full_chain`, `privileged_account` and `restricted_probe`
  reach 100%. **`bulk_export` alone is only 3.3%**: a large download by itself is not unusual enough in the feature
  space. That is expected and is exactly why the ML score is only one of five inputs: the `large_export` rule and the
  correlation with other stages cover it. These figures describe synthetic data and say nothing about real banks.

## Detection rules in detail

The rules are data, not code: `backend/detection_rules.json` (18 rules, hot-reloadable). Every rule has a *severity*
between 0 and 1 and, where relevant, an attack *stage*. A rule only counts as evidence if its severity is at least
`min_evidence_severity` (0.10); weaker flags are kept on the event for context but do not add to the score.

| Rule | Severity | Stage | Fires when |
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
| `unusual_outbound_transfer` | 0.38 | Collection | an external transfer by an employee with no earlier transfers, or one at or above the large-export threshold |
| `external_transfer_confirmed` | 0.72 | Exfiltration | an external transfer that succeeded with status `confirmed` |
| `permission_change_attempt` | 0.40 | Privilege Escalation | a permission-change event, or a denied administrative action |
| `privileged_account_created` | 0.58 | Privilege Escalation and Persistence | a privileged account was created (scaled down for routine IT work) |
| `new_account_login` | 0.45 | Lateral Movement | login to an account created in the last 24 hours |

**Context decides, not the bare event.**

* A new IP alone is a weak signal (0.18). An employee logging in from a new address and opening a permitted document
  stays Normal or Suspicious; it is the combination with other stages that raises the score.
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

### Attack confidence (`backend/threat_engine.py`)

```
confidence = 100 x ( 0.20 x ML anomaly
                   + 0.30 x rule severity
                   + 0.25 x correlated evidence
                   + 0.10 x baseline deviation
                   + 0.15 x attack stage )
```

* Each component is first bounded to 0-1 and the weights sum to 1, so the score can never leave 0-100 however many
  events arrive.
* **Rule severity** is a noisy-OR of the evidence severities, so many weak signals do not add up linearly.
* **Correlated evidence** maps the number of independent stages through the curve `[0, 0.12, 0.40, 0.65, 0.82, 0.93, 1.0]`.
* **Attack stage** uses the weight of the furthest stage reached: Initial Access 0.15, Credential Misuse 0.30,
  Sensitive Resource Access 0.35, Collection 0.55, Privilege Escalation 0.70, Persistence 0.80, Lateral Movement 0.80,
  Exfiltration 1.0.
* **Stage gates:** with fewer than 2 independent stages the score cannot exceed High Risk, with fewer than 3 it cannot
  be Critical. One loud signal, however strong, therefore cannot raise a critical alert on its own.
* The whole-number score is floored so it always matches its severity band.

| Score | Severity |
|---|---|
| 0-24 | Normal |
| 25-49 | Suspicious |
| 50-79 | High Risk |
| 80-100 | Critical (raises an alert) |

All thresholds, weights and curves are configurable (`.env` for thresholds, `detection_rules.json` for the rest).

A typical simulated run: the confidence goes about 33 (unfamiliar login) to 66 (restricted access) to **81 at the
large export, which raises the critical alert and creates the investigation**, then 88, 95 and 97 as the later steps
arrive, ending near 99.9 after the external transfer. The alert exists before the final transfer happens.

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

## The simulated attack, step by step

Target default `EMP-1004` (David Kumar, IT administrator), attacker IP `185.220.101.45`, device
`SimulatedAttackerToolkit/1.0 (Linux x86_64; synthetic)`, external destination `files.exfil-sim.example.invalid`.
The attacker uses the target's stolen password through the normal login code path.

| # | Step | What the backend records | Why it is suspicious | Stage |
|---|---|---|---|---|
| 1 | Login from unfamiliar IP | `login` from `185.220.101.45` | IP is not in the employee's baseline; weak on its own | Initial Access |
| 2 | Access restricted resources | `resource_access` on HR, payroll, IT admin console, audit, loans; results `success` or `denied` by the real permission check | denied restricted probes and rapid enumeration across departments | Sensitive Resource Access |
| 3 | Large export | `data_export` or `file_download` of the chosen number of records (default 25,000) from the most sensitive resource the account can reach | far above the employee's history | Collection |
| 4 | Failed administrator logins | five `login_failed` events against the admin console | password guessing; `failed_login_burst` and `admin_console_login_failed` | Credential Misuse |
| 5 | Privileged account creation | `administrative_action` creating `svc.backupNN` with write access to every managed resource (only succeeds if the target has IT admin console write access) | a new privileged account is a persistence mechanism | Privilege Escalation, Persistence |
| 6 | Login with the new account | `login` as `svc.backupNN` | new account used within 24 hours; attributed to the employee that created it | Lateral Movement |
| 7 | External data transfer | `external_transfer` to the external destination, status `confirmed` | records leave the organisation | Exfiltration |

The second scenario, `finance_data_theft` (Alice Morgan), runs steps 1 to 4 and 7: a standard employee cannot create
accounts, restricted access is denied by the backend and exports are limited to her own data.

The critical alert appears by step 3 or 4, **before step 7**. Step 7 is stored as its own `external_transfer` event with
the records counted separately from the earlier export, so the exposure shows `confirmed_export` first and
`confirmed_external_transfer` only after step 7.

## How attacks are prevented, contained and what is not prevented

This project is about **detection and response**. It does not claim to stop a real attacker on a real network. The
controls below work inside the application and the simulation.

### Preventive controls that are always on

| Control | What it stops | Where |
|---|---|---|
| PBKDF2-SHA256 salted hashes (260,000 iterations) | stolen database revealing passwords | `backend/security.py` |
| Equal-time check for unknown employee IDs | user enumeration by timing | `auth_service.authenticate` |
| Random session tokens, only an HMAC is stored, 480-minute lifetime, revocation | stolen database revealing live sessions; sessions that never expire | `security.py` |
| Backend decides identity, IP and device | an attacker choosing a different employee ID or IP in a request | `security.get_auth`, `resolve_ip` |
| Role-based access control (`security_admin` vs `employee`) | employees reaching the SOC, simulation or response endpoints | `require_admin` |
| Per-resource permission checks on every access | reading or exporting data the role is not granted | `event_service.has_access` |
| Self-only profile endpoint | reading another employee's private record | `portal_routes.py` |
| Input validation (Pydantic), integer overflow limits, safe error handling | malformed requests, crashes, stack-trace leaks | `schemas.py`, `main.py` |
| Idempotency keys | replayed requests being counted twice | `record_event` |
| Append-only evidence with SHA-256 | tampering with an investigation unnoticed | `investigation_service.py` |
| Audit log of logins, account creation, response and failed responses | actions without accountability | `write_audit` |

### Detective controls (what raises the alarm)

Hybrid detection: Isolation Forest anomaly score, 18 rules, a per-employee 30-day baseline, correlation of related
events in a 4-hour window, attack-stage classification and a bounded 0-100 confidence. An alert is raised at 80, which
is designed to be before the last attack step. Unusual-but-innocent behaviour (new IP, late shift, large legitimate job)
is tuned not to reach that threshold alone.

### Response controls (what a security administrator can do)

Every action needs a security-administrator session, a written reason and, for disruptive actions, `confirm: true`. Each
records who, when and why, changes backend state and writes an audit log. Failures are audited as `containment_failed`.

| Action | Effect inside the simulated environment |
|---|---|
| Disable employee account (`lock_account`) | status becomes locked, open sessions are revoked, new logins return 403 |
| Revoke active sessions (`revoke_sessions`) | every open session of the employee is ended immediately |
| Block source IP (`block_ip`) | logins and requests from that IP are refused and its open sessions are revoked |
| Remove unauthorised privileges (`remove_privileges`) | write access is downgraded to read; on an account created during an incident (such as `svc.backupNN`) every permission is deleted |
| Restrict access to a resource (`restrict_access`) | removes the employee's confidential and restricted permissions, or only the chosen resource |
| Isolate a system (`isolate_system`) | that resource denies every employee until it is released |
| Resolve investigation (`resolve_investigation`) | marks it resolved with a reason (a later critical alert opens a new one) |
| Restore account, unblock IP, release system | undo the three disruptive actions; no confirmation needed |

### What is deliberately not covered

* No rate limiting, account throttling, MFA or password reset. Brute force is *detected* (burst rules) but not slowed down.
* Containment only changes application state. A real deployment would connect it to a firewall, identity provider and
  endpoint agents.
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
figure comes from the backend. Live panels poll a small change token every 3 seconds and only reload when something
changed, so filters and navigation are kept.

| Page | Content |
|---|---|
| Security Overview | KPIs (total events, active investigations, critical alerts, high-risk employees, sensitive records accessed, confirmed external transfers), live attack-confidence meter, active threats |
| Live Event Feed | events with anomaly score, risk contribution and stage; filters for employee, IP, event type, severity, time range |
| Attack Investigations | list; selecting one opens the investigation (findings, case file, containment, export, resolve) |
| Employee Risk Monitor | employees ranked by behavioural and rule evidence only (no names or demographics) |
| Attack Timeline | the eight stages built from correlated events, current stage highlighted |
| Attack Graph | accounts, IPs, sessions, systems, privileged accounts and external destinations from stored events |
| Response Centre | recommended containment, active controls, history, manual response |
| Audit Logs | alerts, investigation updates, containment, administrator actions, failed responses |

The risk monitor deliberately ranks only by activity evidence; names, demographics or other personal traits are never
used as risk indicators.

## Investigation and incident response

A critical alert creates one investigation per employee, and every later related event updates it.

* **Case file:** sessions, suspicious IPs, related privileged accounts, first and latest suspicious event, confidence,
  stage, sensitive resources accessed, records exported, potentially exposed and confirmed external transfers.
* **Status:** `open`, `contained` or `resolved`.
* **Preserved evidence:** related events are collected by employee, session, IP, created account, resource and time and
  copied once into the append-only `investigation_evidence` table with a SHA-256 of the original. Nothing edits events;
  the evidence view and every export compare each copy with the live event (`verified`, `modified`, `missing`).
* **Explanation** (`investigation_explainer.py`, engine `deterministic-evidence-v1`): deterministic, no LLM or network
  call. It gives the likely attack type, stage, suspicious activities, supporting evidence, confidence, impact,
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

### Database tables

| Table | Purpose |
|---|---|
| `employees` | identity, department, role, status (`active`/`locked`), password hash, known IPs, synthetic flag, creator of privileged accounts |
| `employee_sessions` | token hash, IP, device, created, expires, revoked, synthetic flag |
| `access_permissions` | employee, resource, `read` or `write` |
| `security_events` | one row per action: employee, session, UTC time, type, resource, outcome, IP, device, records accessed and downloaded, details JSON, `request_id`, synthetic flag, scenario |
| `risk_assessments` | per-event scores: anomaly score, risk contribution, confidence, severity, stage, factors |
| `security_alerts` | critical alerts with evidence, exposure, first and triggering event, recommended actions |
| `attack_investigations` | case file and status linked to the alert |
| `investigation_evidence` | append-only evidence copies with SHA-256 hashes |
| `containment_actions` | action, reason, performing administrator, time, status |
| `response_controls` | the active blocks, isolations and restrictions the enforcement points consult |
| `audit_logs` | actor, action, target, IP, details, time |

All tables have timestamps and indexes on their lookup columns (employee, time, status and severity).

## Project structure

```
app.py                       launcher (loads .env, starts backend and dashboards)
backend/                     FastAPI app, models, detection, correlation, investigation, response, SOC read models
  detection_rules.json       configurable rules, weights and parameters
data/                        demo_accounts.py (credentials), seed_data.py (history), the SQLite file (git-ignored)
ml/                          features.py, synthetic_data.py, train_model.py, anomaly_detector.py, artifacts/ (git-ignored)
frontend/                    employee_portal.py, soc_dashboard.py, simulation_console.py, components, theme, api_client
tests/                       134 pytest tests
.streamlit/config.toml       Streamlit theme and server settings
requirements.txt  .env.example
```

## Tests

```powershell
python -m pytest tests -q          # 134 tests, 1 to 2.5 minutes
```

The suite uses a temporary database and a separate backend process, and an autouse fixture resets the simulation and
removes rows each test creates. It covers:

* **Integration:** a normal employee's session is recorded and scored low; a compromised account (unfamiliar IP, restricted
  payroll access, an 8,000-record export, failed administrator logins, IT portal probe, privileged account and login,
  external transfer) is detected with rising confidence, correlated, alerted **before the external transfer**, shown on
  the timeline and graph, investigated, and contained; a new-IP login to a permitted resource is **not** critical.
* **Security and reliability:** hashed passwords and session tokens; every endpoint requires authentication except health
  and login; admin endpoints reject employees; employees cannot read other employees' restricted records; invalid
  paths, queries and bodies never produce a 5xx; audit entries; UTC timestamps; bounded scores that match the severity bands.
* **Runtime:** data, sessions and the model survive a backend restart; the three Streamlit apps run against a live backend,
  employees are refused by the SOC dashboard, and the apps stay usable when the backend is unreachable.
* **Detection, ML, SOC and investigation workflow:** normal activity, unfamiliar IP, restricted access, large export,
  failed logins, privileged account creation, external transfer, a complete attack, duplicate events, false positives,
  evidence preservation and tamper detection, containment enforcement and report export.

## Known limitations

* **Local demonstration only.** It is not hardened for production: HTTP only, no MFA, no password reset, no login rate
  limiting or account throttling, and the default `SECRET_KEY` must be changed.
* **Synthetic data.** The model is trained on generated sessions; its metrics, the rule severities and the scoring weights
  are hand-tuned for the case study and would need real data and tuning before any real use.
* **ML alone misses a bare bulk export** (3.3% recall); the `large_export` rule and correlation cover that case.
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
