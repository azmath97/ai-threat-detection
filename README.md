# AI-Based Insider Threat Detection System

Cybersecurity case study: a simulated financial organisation where an employee account may be compromised or
misused. A single **FastAPI backend + SQLite database** is the source of truth for two dashboards
(Employee Workspace Portal and SOC Dashboard, Streamlit - built in the next phase).

**This phase: backend, database, event pipeline and API.** All data is synthetic. No real credentials,
personal or banking data is used.

## How it works

```
event (login / resource access / download / export ...)
   -> event_service.record_event      persist to SQLite
   -> detection_engine                explainable rule scoring + sliding-window risk score (0-100)
   -> correlation_engine              maps flagged events to kill-chain stages
   -> alert + investigation report    raised when risk is high/critical or a multi-stage chain is found
   -> response_service                SOC containment (revoke sessions, lock, restrict access, restore)
```

Kill-chain stages: `initial_access -> discovery -> privilege_escalation -> collection -> exfiltration`.
Risk levels (configurable): low < 25 <= medium < 50 <= high < 75 <= critical.

## File structure

```
ai-threat-detection/
├── app.py                         # starts the backend (uvicorn)
├── backend/
│   ├── main.py                    # FastAPI app + all endpoints
│   ├── config.py                  # env-driven settings, UTC -> local conversion
│   ├── database.py                # SQLAlchemy engine/session, UTC datetime type
│   ├── models.py                  # 9 tables
│   ├── schemas.py                 # request/response validation
│   ├── security.py                # password hashing, session tokens, RBAC dependencies
│   ├── catalog.py                 # synthetic resources + event vocabulary
│   ├── event_service.py           # event pipeline, alerts, audit logging
│   ├── detection_engine.py        # risk scoring rules
│   ├── correlation_engine.py      # attack chain correlation
│   ├── investigation_service.py   # investigation reports
│   ├── response_service.py        # containment actions
│   └── errors.py
├── data/seed_data.py              # synthetic employees + 14 days of history
├── tests/                         # pytest suite
├── requirements.txt  .env.example  .gitignore  README.md
```

Planned next: `frontend/` (employee portal, SOC dashboard) and `ml/` (Isolation Forest anomaly detector).

## Install

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env      # optional; defaults work out of the box
```

## Run the backend

```powershell
python app.py               # http://127.0.0.1:8000  (docs: /docs)
# or: uvicorn backend.main:app --reload
```

If port 8000 is busy: `$env:API_PORT="8010"; python app.py`.
On first start the SQLite database (`data/insider_threat.db`) is created and seeded automatically.
Rebuild it with `python -m data.seed_data --reset`.

## Demo credentials (local demonstration only - synthetic accounts)

| Account | Username | Password | Role |
|---|---|---|---|
| Demo employee (Finance) | `alice.morgan` | `Employee#Demo2026` | employee |
| Security administrator | `soc.admin` | `SocAdmin#Demo2026` | security_admin |

The other nine employees (`bob.chen`, `carol.diaz`, `david.kumar`, `emma.wilson`, `frank.osei`, `grace.lee`,
`henry.novak`, `isla.murphy`, `jack.silva`) use the same employee password. Passwords are stored only as salted
PBKDF2-SHA256 hashes; session tokens are random, stored as HMAC hashes, expire, and can be revoked.
Change `SECRET_KEY` and the demo passwords in `.env` for anything beyond a local demo.

## API endpoints

Auth is `Authorization: Bearer <token>` from `/api/auth/login`. "Admin" = `security_admin` role.

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/health` | public | Liveness |
| POST | `/api/auth/login` | public | Login (optional `source_ip` to simulate an origin) |
| POST | `/api/auth/logout` | any | Revoke session |
| GET | `/api/employees/me` | any | Own profile + permissions |
| GET | `/api/employees` | admin | List employees |
| GET | `/api/employees/{id}` | self/admin | Profile |
| GET | `/api/resources` | any | Resource catalogue with my access level |
| POST | `/api/resources/{id}/access` | any | View/download/export (403 if not permitted; always logged) |
| POST | `/api/events` | any | Create event (admins may set `employee_id`) |
| GET | `/api/events` | admin | History; filters: `employee_id,event_type,outcome,since,until,min_risk_points,limit,offset` |
| GET | `/api/events/me` | any | Own activity |
| GET | `/api/risk/employees` | admin | Current risk of every employee |
| GET | `/api/risk/employees/{id}` | admin | Score, factors, attack stages, history |
| POST | `/api/risk/assess` | admin | Re-assess an employee now |
| GET | `/api/alerts`, `/api/alerts/{id}` | admin | Alerts (filters: `status,severity,employee_id`) |
| PATCH | `/api/alerts/{id}` | admin | Set status |
| GET | `/api/investigations`, `/api/investigations/{id}` | admin | Investigation reports |
| POST | `/api/investigations` | admin | Build/refresh report for an employee |
| PATCH | `/api/investigations/{id}` | admin | Close/reopen |
| POST | `/api/containment` | admin | `revoke_sessions`, `lock_account`, `restrict_access`, `restore_account` |
| GET | `/api/containment` | admin | Containment history |
| GET | `/api/dashboard/stats` | admin | KPIs, charts data, top-risk employees |
| GET | `/api/audit-logs` | admin | Audit trail |

Timestamps are stored in UTC. Responses contain the UTC value (`timestamp`) and the display-timezone value
(`timestamp_local`, `DISPLAY_TIMEZONE`, default `Asia/Kolkata`).
`source_ip` overrides exist so the demo can simulate a login from an unfamiliar network
(`ALLOW_SIMULATED_SOURCE_IP=false` disables them).

## Example attack simulation

```powershell
$b="http://127.0.0.1:8000"; $bad="198.51.100.77"
1..3 | % { try { Invoke-RestMethod "$b/api/auth/login" -Method Post -ContentType application/json -Body (@{username="frank.osei";password="guess";source_ip=$bad}|ConvertTo-Json) } catch {} }
```
Then log in as `frank.osei` from that IP, request `payroll-records` / `hr-records`, download and export
`customer-accounts` with a large `record_count`: the backend raises a critical alert with an investigation report,
which `soc.admin` can contain via `POST /api/containment`.

## Tests

```powershell
python -m pytest tests -q
```
The suite uses a temporary SQLite database and covers seeding, hashing, auth/RBAC, validation, event persistence
(verified by reading the SQLite file directly), attack-chain detection, alerts, investigations and containment.
