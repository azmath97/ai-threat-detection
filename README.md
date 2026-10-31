# AI-Based Insider Threat Detection System

Cybersecurity case study: a simulated financial organisation ("Meridian Trust Bank") where an employee account may
be compromised or misused. One **FastAPI backend + SQLite database** is the single source of truth for every
front end. All data is synthetic; no real credentials, personal or banking data is used.

| Phase | Status |
|---|---|
| Backend, database, event pipeline, API | done |
| **Employee Workspace Portal** (Streamlit) + admin simulation console | done |
| SOC Dashboard, ML anomaly detector | next |

## How it works

```
Employee Portal  --HTTP-->  FastAPI backend  --> SQLite (shared)  <-- SOC Dashboard (next phase)
Simulation Console --HTTP-->      |
                                  +-- every action -> security event -> risk scoring -> correlation -> alert/investigation
```

* The portal holds only a session token. **The backend decides identity, permissions, source IP and session.**
  The browser cannot set an employee ID or a source IP on any request.
* The portal never shows risk scores, attack confidence, investigations or alerts.
* Kill-chain stages: `initial_access -> discovery -> privilege_escalation -> collection -> exfiltration`.
  Risk levels: low < 25 <= medium < 50 <= high < 75 <= critical (configurable). Contextual signals
  (off-hours, unfamiliar IP, repeat access to one restricted resource) score once per window, not once per click.

## File structure

```
ai-threat-detection/
├── app.py                          # launcher: backend | portal | simulation | all
├── backend/
│   ├── main.py                     # FastAPI app, auth/events/risk/alerts/containment/dashboard endpoints
│   ├── portal_routes.py            # employee portal endpoints (payslips, HR, documents, directory, accounts)
│   ├── simulation_routes.py        # admin-only simulation endpoints
│   ├── auth_service.py             # login + account creation (shared by portal and simulation)
│   ├── event_service.py            # event pipeline: persist -> score -> correlate -> alert
│   ├── detection_engine.py  correlation_engine.py  investigation_service.py  response_service.py
│   ├── simulation_service.py       # attack steps + reset
│   ├── portal_data.py              # deterministic synthetic payslips, HR data, documents
│   ├── models.py  database.py  schemas.py  security.py  catalog.py  config.py  errors.py
├── frontend/
│   ├── employee_portal.py          # Employee Workspace Portal
│   ├── simulation_console.py       # separate, administrator-only simulation control panel
│   ├── components.py  api_client.py
├── .streamlit/config.toml          # enterprise light theme
├── data/seed_data.py               # synthetic employees + 14 days of history
├── tests/                          # pytest suite (14 tests)
└── requirements.txt  .env.example  README.md
```

## Install and run

```powershell
python -m venv .venv; .venv\Scripts\Activate.ps1
pip install -r requirements.txt

python app.py all          # backend :8000, Employee Portal :8501, Simulation Console :8502
```

Or run the parts separately: `python app.py` (backend), `python app.py portal`, `python app.py simulation`.
If port 8000 is busy: `$env:API_PORT="8010"; python app.py all`. The SQLite database
(`data/insider_threat.db`) is created and seeded on first start (`python -m data.seed_data --reset` rebuilds it;
databases from earlier versions are upgraded in place).

## Demo credentials (local demonstration only; synthetic accounts)

Sign in with the **Employee ID** and password.

| Account | Employee ID | Password | Notes |
|---|---|---|---|
| Demo employee (Finance analyst) | `EMP-1001` | `Employee#Demo2026` | own payslips, permitted documents |
| HR manager | `EMP-1003` | `Employee#Demo2026` | HR records, payroll register (read only) |
| Payroll specialist | `EMP-1002` | `Employee#Demo2026` | payroll register + CSV export |
| IT administrator | `EMP-1004` | `Employee#Demo2026` | can create privileged accounts |
| Security administrator | `SEC-9011` | `SocAdmin#Demo2026` | SOC / simulation console |

`EMP-1005` ... `EMP-1010` (Emma Wilson, Frank Osei, Grace Lee, Henry Novak, Isla Murphy, Jack Silva) use the same
employee password. Passwords are stored only as salted PBKDF2-SHA256 hashes; session tokens are random, stored as
HMAC hashes, expire and can be revoked.

## Employee Workspace Portal (http://127.0.0.1:8501)

Sidebar: Dashboard, HR Records, Payroll, Documents, Employee Directory, My Profile, Logout.

| Page | What you can do | Backend rule |
|---|---|---|
| Dashboard | name, employee ID, department, role, last login, available resources, recent activity | own data only |
| HR Records | search records, open an employee record | needs `hr-records` access (HR) |
| Payroll | view own payslips; payroll register; export CSV | register needs `payroll-records` read, export needs write |
| Documents | list permitted documents, request a download | per-document resource permission |
| Employee Directory | search by name / role / department | all employees |
| My Profile | personal and employment information | own data only |

Pages for resources outside your role show an "access restricted" notice, and the backend refuses (403) and records
the attempt if the endpoint is called anyway.

### Events collected (table `security_events`)

Every meaningful action is a row: event ID, employee ID (from the session), session ID, UTC timestamp, event type,
resource, source IP (derived by the backend), device information, outcome (`success` / `failure` / `denied`),
`records_accessed`, `records_downloaded`, JSON metadata, `is_synthetic`, `scenario`.
Types: `login`, `login_failed`, `logout`, `resource_access` (incl. denied), `file_download`, `data_export`
(payroll export), `directory_search`, `administrative_action`, `external_transfer`, `permission_change_attempt`.

Local demo note: the browser, portal and backend all run on one machine, so the backend sees loopback connections.
With `MAP_LOOPBACK_TO_WORKSTATION=true` (default) these are attributed to the employee's registered workstation IP;
any non-loopback peer address is stored as seen.

## Simulation Console (http://127.0.0.1:8502, security administrators only)

A separate control panel, clearly labelled **SIMULATION ENVIRONMENT - SYNTHETIC DATA ONLY**. Employees are rejected,
and the `/api/simulation/*` endpoints return 403 for non-administrators (or for everyone when
`SIMULATION_ENABLED=false`). Select a scenario, the compromised employee account and the attacker's source IP, then
run steps one by one or the whole chain:

1. Login from an unfamiliar IP (real authentication flow, stolen-credential login)
2. Access to restricted resources (real permission checks: granted or denied per role)
3. Large record export (25,000 records)
4. Five failed administrator-console logins
5. Privileged account creation (needs IT admin-console write access, otherwise denied and logged)
6. Login with the newly created privileged account
7. External data transfer to a non-routable synthetic destination

Steps run through the same authentication, permission, event-collection and detection code as normal employee
traffic (there is no separate fake attack dashboard); the console only controls them. Everything created is
flagged `is_synthetic` (events, sessions, alerts, investigations, accounts) with the scenario name and a
`"synthetic": true` marker in the event metadata. Accounts created by an employee are attributed to their creator
for risk, correlation and alerting. **Reset simulation** removes all synthetic data, undoes containment applied to
the affected employees and restores their last-login time. Run the simulation on accounts that are not in active
use: genuine activity during a run is scored in the same window.

## API

Auth is `Authorization: Bearer <token>`. "Admin" = `security_admin` role. Interactive docs: `/docs`.

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` | public | body `employee_id` + `password` (username also accepted) |
| POST | `/api/auth/logout` | any | revoke session |
| GET | `/api/employees/me` | any | profile, permissions, previous login |
| GET | `/api/employees`, `/api/employees/{id}` | admin / self | directory (admin), profile |
| GET | `/api/resources`, POST `/api/resources/{id}/access` | any | catalogue; view/download/export (403 if not permitted) |
| GET | `/api/portal/profile` | any | own profile detail |
| GET | `/api/portal/payslips`, `/api/portal/payslips/{period}` | any | own payslips |
| GET / POST | `/api/portal/payroll/register`, `/api/portal/payroll/export` | payroll access | register / CSV export |
| GET | `/api/portal/hr/records`, `/api/portal/hr/records/{employee_id}` | HR access | search / open record |
| GET | `/api/portal/documents`, `/api/portal/documents/{id}/download` | per document | list / download |
| GET | `/api/portal/directory`, `/api/portal/directory/departments` | any | search directory |
| POST | `/api/admin/accounts` | IT admin console write | create privileged account |
| POST | `/api/events` | any | telemetry for the caller only (identity/IP/device set by backend) |
| GET | `/api/events` | admin | history; filters `employee_id,event_type,outcome,since,until,min_risk_points,synthetic,limit,offset` |
| GET | `/api/events/me` | any | own activity (no risk data) |
| GET | `/api/risk/employees[/{id}]`, POST `/api/risk/assess` | admin | risk scores, factors, attack stages |
| GET / PATCH | `/api/alerts[/{id}]` | admin | alerts |
| GET / POST / PATCH | `/api/investigations[/{id}]` | admin | investigation reports |
| GET / POST | `/api/containment` | admin | `revoke_sessions`, `lock_account`, `restrict_access`, `restore_account` |
| GET | `/api/dashboard/stats`, `/api/audit-logs` | admin | KPIs, audit trail |
| GET / POST | `/api/simulation/scenarios`, `/status`, `/steps`, `/run`, `/reset` | admin + simulation enabled | attack simulation |

Timestamps are stored in UTC; responses carry both `timestamp` (UTC) and `timestamp_local` (`DISPLAY_TIMEZONE`,
default `Asia/Kolkata`).

## Tests

```powershell
python -m pytest tests -q
```
The suite uses a temporary SQLite database and covers seeding and hashing, employee-ID login, RBAC, that
client-supplied employee IDs and IPs are ignored, portal flows per role, event fields persisted in SQLite, that
ordinary working sessions never alert, the full simulated attack (detection, alert, investigation, containment,
reset) and the simulation being unavailable to employees.
