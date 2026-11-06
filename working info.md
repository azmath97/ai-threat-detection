# Working Info: how the whole system works

A complete walkthrough of the **AI-Based Insider Threat Detection System** (Westbridge Bank): what it is, what it can do, how it
detects, how it responds, how every score is calculated, when scores go back to normal, the workflow from a click to an incident, the
technology used, and what is and is not real. It is written for a demo or a viva. The [README](README.md) is the long reference;
this file is the explanation.

**Contents**

1. [What this project is, and what it is not](#1-what-this-project-is-and-what-it-is-not)
2. [Technology stack](#2-technology-stack)
3. [Architecture and processes](#3-architecture-and-processes)
4. [Features available](#4-features-available)
5. [The workflow, step by step](#5-the-workflow-step-by-step)
6. [How attacks are detected](#6-how-attacks-are-detected)
7. [How attacks are prevented and responded to](#7-how-attacks-are-prevented-and-responded-to)
8. [How the score works](#8-how-the-score-works)
9. [How much one event moves the score, and why](#9-how-much-one-event-moves-the-score-and-why)
10. [When does the score go back to normal](#10-when-does-the-score-go-back-to-normal)
11. [Investigations and evidence](#11-investigations-and-evidence)
12. [The database](#12-the-database)
13. [The API](#13-the-api)
14. [Security design](#14-security-design)
15. [Machine learning and evaluation results](#15-machine-learning-and-evaluation-results)
16. [Running it, demoing it, and the attack drill](#16-running-it-demoing-it-and-the-attack-drill)
17. [Deployment status](#17-deployment-status)
18. [Project structure and tests](#18-project-structure-and-tests)
19. [Limits and honest caveats](#19-limits-and-honest-caveats)
20. [Glossary](#20-glossary)

---

## 1. What this project is, and what it is not

**What it is.** A security-monitoring and response platform for a fictional bank, *Westbridge Bank*. Employees use a **Portal**; a
security team watches the same backend through a **SOC (Security Operations Centre) dashboard**. The backend records every sign-in and
every refused request as it happens, detects brute force, credential stuffing, probing of other people's records, bulk exports and
compromised-account behaviour, and responds: it locks accounts, refuses addresses, holds big exports for approval, and opens
investigations with preserved evidence.

**What is real.**
* The detection code runs on the requests this application actually receives. Nothing is replayed or scripted inside the product.
* The enforcement is real *inside the application*: a locked account cannot sign in, its sessions stop working, a blocked address is
  refused by the login code, a removed permission denies access, and a bulk export is held until a security administrator approves it.
  The backend checks all of this on every request.

**What is not real.**
* All employees, accounts and history are **synthetic**. There is no real credential, personal data or banking data.
* **Nothing outside the application is touched.** It does not block real network traffic, does not disable real accounts, does not
  quarantine real devices, does not send email, does not contact a directory, firewall or endpoint agent, and does not protect a real
  bank. An address "block" is a refusal by this application's own code, **not a firewall rule**.
* It has not been validated on real traffic. The thresholds are starting values calibrated on synthetic runs. It is a research and
  teaching project, not a security product.

---

## 2. Technology stack

| Layer | Technology | Used for |
|---|---|---|
| Language | Python 3.12 | everything |
| Backend API | **FastAPI** + Uvicorn, **Pydantic 2** | the single source of truth: authentication, permissions, events, detection, alerts, investigations, containment |
| Database access | **SQLAlchemy 2** with versioned migrations (`backend/migrations.py`) | tables, constraints, indexes, transactions |
| Database | **SQLite** for local use; **PostgreSQL** (via `psycopg` 3) when `DATABASE_URL` points at it | persistent storage, UTC timestamps |
| Dashboards | **Streamlit** (two apps: Employee Portal, SOC dashboard) + **Plotly** | the user interfaces, charts, the attack graph |
| Machine learning | **scikit-learn** `IsolationForest`, **NumPy**, **pandas**, **joblib** | anomaly score, dataset preparation, model file |
| Password security | **Argon2id** (`argon2-cffi`) | password hashes (never stored in plain text) |
| Sessions | random tokens, only an **HMAC** is stored | revocable sessions, 480-minute life |
| HTTP client | `requests` | dashboards call the backend |
| Configuration | environment variables + `python-dotenv` (`.env`) | all thresholds and settings |
| Tests | **pytest**, `httpx` (FastAPI TestClient), Streamlit `AppTest` | 571 automated tests |
| Deployment (prepared, not deployed) | **Docker**, a small gateway (`deploy/gateway.py`), Render blueprint (`render.yaml`) | one-container hosting |
| Datasets | synthetic demo data; **CERT Insider Threat Test Dataset r4.2** (synthetic benchmark, CC BY 4.0, not shipped in the repo) | training and evaluation |

---

## 3. Architecture and processes

```
 Employee Portal (Streamlit :8501) ---\
                                        >--- HTTP/JSON ---> FastAPI backend (:8000) ---> SQLite (local) / PostgreSQL (DATABASE_URL)
 SOC Dashboard   (Streamlit :8503) ---/                              |
                                                                     +-- Isolation Forest model (ml/artifacts/*.joblib)
                                                                     +-- rules (backend/detection_rules.json)
                                                                     +-- auth-defence policy (backend/auth_policy.py)
```

* **One backend, one database.** Both dashboards only call the backend. Neither has its own data, scores or event system, so they
  always show the same records.
* **Three local processes:** backend `:8000`, portal `:8501`, SOC dashboard `:8503`. `python app.py all` starts them.
* **Who decides identity.** The backend decides who you are and where you came from. A browser can never choose its own employee ID or
  source address. The dashboards may *report* a client address to the backend, and the backend believes it only because the request
  also carries a shared secret (`TRUSTED_FRONTEND_KEY`) that only the dashboards hold.
* **Time.** Everything is stored in UTC and shown in the display time zone (`DISPLAY_TIMEZONE`, default `Asia/Kolkata`).

---

## 4. Features available

### Employee Workspace Portal (http://127.0.0.1:8501)

| Page | What an employee can do |
|---|---|
| Dashboard | own name, ID, department, role, last login, the resources they may use |
| HR Records | search and open HR records (needs HR access) |
| Payroll | own payslips; the payroll register; CSV export (register needs read, export needs write access) |
| Documents | list and download documents they are permitted to see |
| Employee Directory | search colleagues by name, role or department |
| My Profile | own personal and employment information |

The portal never shows risk scores, alerts or investigations. Every meaningful action becomes a stored security event.

### SOC dashboard (http://127.0.0.1:8503, security administrators only)

| Page | What it shows or does |
|---|---|
| **Security Overview** | KPIs (events, active investigations, active alerts, employees in the Elevated/Alert band, sensitive records accessed, confirmed external transfers), a live risk meter, active threats, and a "How to read the scores" panel |
| **Live Event Feed** | every event with its anomaly score, rule points and attack stage; filters for employee, IP, event type, risk band, time |
| **Attack Investigations** | active and past investigations; open one for findings, evidence, explanation, containment, export, resolve |
| **Employee Risk Monitor** | employees ranked by behaviour and rule evidence only (never by name or personal traits) |
| **Attack Timeline** | the eight attack stages built from correlated events, with the current stage highlighted |
| **Attack Graph** | accounts, IP addresses, sessions, systems and external destinations and how they relate |
| **Authentication Defence** | real sign-in attempts, refused requests, incidents with evidence, locked accounts, blocked addresses, export approvals, response history, the policy in force |
| **Response Centre** | recommended containment, active controls, history of actions with results, manual response |
| **Audit Logs** | every alert, investigation update, containment action and administrator action |

The SOC page refreshes itself: it checks a small change token every `SOC_REFRESH_SECONDS` (3 s) and reloads panels only when something
changed.

### Platform features

* **Real sign-in monitoring:** every attempt (success, failure, refused) is stored; unknown usernames are kept only as a keyed hash.
* **Real refusal monitoring:** every `401` and `403` the API returns is recorded (route, object asked for, address, account; never a token).
* **Automatic response policy:** lock accounts, revoke sessions, refuse addresses, with expiry, caps and safeguards (section 7).
* **Bulk-export control:** large exports are held for approval; approvals are single-use.
* **Insider-threat detection:** 19 rules + an Isolation Forest + a 30-day per-employee baseline + correlation into attack stages.
* **Explainable scoring:** every score can be taken apart into rules, events, model output, thresholds.
* **Investigations:** one per employee, with append-only, hash-checked evidence and a deterministic written explanation.
* **Containment actions:** lock, revoke, block, restrict, remove privileges, isolate, restore; each audited and idempotent.
* **Audit log** of logins, account creation, response and failures.
* **Persistence:** SQLite or PostgreSQL, migrations, constraints, indexes, de-duplication of events.
* **Attack drill:** a command-line client that sends real requests to the running backend (section 16).
* **Offline scenario lab:** the old seeded simulator, kept only for tests and threshold calibration (not in the product or the image).

---

## 5. The workflow, step by step

### 5.1 From a click to a stored event

1. A person signs in or acts in the portal (or an API client sends a request).
2. The backend authenticates the session, decides the **identity**, **source address** and **device** itself (the client cannot choose).
3. It checks **permissions**. Not permitted: the request is refused (`403`), the refusal is recorded, and nothing is returned.
4. For exports and downloads it applies the **export policy** (hold, limit or approval).
5. It stores a **security event** (type, resource, address, device, outcome, records accessed and downloaded). A repeated identical
   request (same `Idempotency-Key`) is stored once.
6. The **detection pipeline** runs on that employee's recent events (below).
7. If the result reaches the **Alert** band, an **alert** and an **investigation** are created or updated, with evidence preserved.
8. The SOC dashboard picks the change up within seconds.

### 5.2 The two detection paths

```
  every request
       |
       +--> A. AUTHENTICATION DEFENCE  (sign-in attempts, 401/403 refusals, export requests)
       |        record  ->  count inside a time window  ->  incident (Watch / Elevated / Alert)  ->  automatic response
       |
       +--> B. INSIDER-THREAT PIPELINE (what a signed-in account does)
                event  ->  rules  ->  anomaly model  ->  baseline  ->  correlation into attack stages
                       ->  heuristic risk score  ->  risk band (gated by stages)  ->  alert  ->  investigation
```

Path A catches *getting in* (guessing passwords, stolen credentials tried across accounts, probing other people's records, repeated bulk
requests). Path B catches *what happens after* (a valid account behaving unusually: unfamiliar address, restricted access, large
export, privilege escalation, external transfer).

### 5.3 What a security analyst does

1. Watch **Security Overview** and **Authentication Defence**.
2. Open an incident or investigation. Read the evidence (event IDs, times, rules fired, model output, thresholds).
3. Decide: approve or deny a held export; unlock an account that was locked by mistake; or **Run containment**
   (lock, revoke, block, restrict, remove privileges, isolate). The analyst must give a reason and, for disruptive actions, confirm.
4. Check the history and the **Audit Logs**.
5. Resolve the investigation (with a reason). A later Alert-band alert opens a new one.

---

## 6. How attacks are detected

### 6.1 Path A: authentication defence (real requests, counted in time windows)

Every attempt is stored in `auth_attempts`; the detectors read stored rows inside windows, so counts survive a restart and are the
same on every backend instance. Bands are rule-based (**Watch / Elevated / Alert**), not probabilities.

| Pattern | Default trigger | Automatic response |
|---|---|---|
| **Brute force on one account** | 5 failures in 5 minutes (10 if every failure came from the account's own registered addresses) | lock the account for 15 min and revoke its sessions |
| **Credential stuffing** | 5 different accounts failed from one address in 10 min: Elevated; 10 accounts (or 20 failures): Alert | incident only; at Alert, refuse the address for 60 min |
| **Burst of failures from one address** | 10 failures in 5 min: Elevated; 20 in 10 min: Alert | incident only; at Alert, refuse the address for 60 min |
| **One account attacked from many addresses** | 6 failures from 3 or more addresses in 10 min | lock the account for 15 min |
| **Sign-in after repeated failures** | 3 or more failures in 10 min, then a success from an address **not** registered to the account | revoke sessions (the new one too, so no token is returned), lock the account, refuse the address |
| **Repeated refused requests (403)** | 10 refusals by one account in 5 min: Elevated; 30: Alert | at Alert, end sessions and lock |
| **Probing other people's records (IDOR)** | 5 different objects refused on one route by one account in 5 min: Elevated; 10: Alert | at Alert, end sessions and lock |
| **Flood of unauthenticated requests (401)** | 30 in 5 min from one address: Elevated; 100: Alert | at Alert, refuse the address for 60 min |
| **Repeated bulk-export requests** | 3 held or refused requests in 30 min: Elevated; 6: Alert | at Alert, end sessions and lock |

Notes that avoid false alarms:
* A success from the owner's *own* known address, when the failures came from other addresses, raises nothing.
* A success from a known address that also produced the failures is only flagged ("suspicious").
* Repeating one forbidden call is told apart from probing many records; probing is not also counted as plain repetition.
* Refusals caused by our own enforcement (a locked account, a refused address) are not counted again.

### 6.2 Path B: insider-threat rules (19 hand-weighted rules)

The rules live in `backend/detection_rules.json` and can be reloaded without a restart. A **weight** (0 to 1) says how strongly that
rule alone counts as evidence. It is **not** impact severity and **not** a probability. A rule counts as evidence only if its weight is
at least **0.10**; weaker flags stay on the event for context but add nothing to the score.

| Rule | Weight | Attack stage | Fires when |
|---|---|---|---|
| `unfamiliar_ip` | 0.18 | Initial Access | login or failed login from an address outside the employee's baseline (other events: once per address per window) |
| `off_hours_login` | 0.08 | none | login at a weekend or outside 07:00-19:00, only if the employee's after-hours rate is below 15 % |
| `failed_login` | 0.05 | none | any failed login |
| `failed_login_burst` | 0.38 | Credential Misuse | 3 failed logins within 10 minutes |
| `admin_console_login_failed` | 0.45 | Credential Misuse | failed authentication to the administrator console |
| `login_after_failures` | 0.38 | Credential Misuse | a success after 3 failures within 30 minutes |
| `access_denied` | 0.06 | none | a denied access that is not one of the next two |
| `unauthorised_department_access` | 0.26 | Sensitive Resource Access | denied access to a confidential resource of another department |
| `restricted_denied` | 0.32 | Sensitive Resource Access | denied access to a restricted (level 3) resource |
| `sensitive_access_novel` | 0.12 | Sensitive Resource Access | restricted resource the employee never normally uses outside their own department |
| `rapid_enumeration` | 0.30 | Sensitive Resource Access | 5 or more classified resources touched within 10 minutes |
| `large_export` | 0.42 | Collection | export or download over `max(500, 3 x the employee's largest earlier session download)` |
| `data_export` | 0.08 | none | any ordinary export (context only) |
| `removable_media_copy` | 0.34 (halved below the bulk threshold) | Collection | records of a classified resource copied to removable media |
| `unusual_outbound_transfer` | 0.38 | Collection | an external transfer by an employee with no earlier transfers, or one at or above the large-export threshold |
| `external_transfer_confirmed` | 0.72 | Exfiltration | an external transfer that succeeded and was confirmed |
| `permission_change_attempt` | 0.40 | Privilege Escalation | a permission change, or a denied administrative action |
| `privileged_account_created` | 0.58 | Privilege Escalation, Persistence | a privileged account was created (scaled by 0.45 for routine IT work from a known address in business hours) |
| `new_account_login` | 0.45 | Lateral Movement | login to an account created in the last 24 hours |

**Context decides, not the bare event.** A new address alone is weak (0.18); a late shift is ignored for people who regularly work
late; a large export is judged against that employee's own history; denials caused by a SOC isolation are not scored against the
employee; contextual rules fire once per window so a repeated action does not keep adding.

### 6.3 The per-employee baseline (`backend/baseline.py`)

Built from the previous 30 days up to the start of the current window, so an attacker's own activity can never become "normal". It
holds known addresses (registered ones plus any with at least two successful historical logins), permissions, usual resources, the
after-hours rate, the largest and mean session download, earlier external transfers, and account age (and whether another employee
created the account).

### 6.4 The anomaly model (`ml/`)

An **Isolation Forest** scores each session window on 10 features (login hour, unfamiliar address, failed logins, resources accessed,
departments accessed, download volume, restricted attempts, privilege escalation, external transfer volume, denied accesses). It needs
no attack labels. Its raw score is rescaled to a **0 to 1 anomaly score**: about 0 for ordinary behaviour, towards 1 for clearly
abnormal. A **volume guard** raises the score for volumes far beyond anything seen in training (the forest alone cannot extrapolate).
If the model file is missing or incompatible, a heuristic fallback over the same features is used and the dashboard says so.

### 6.5 Correlation and attack stages (`backend/correlation_engine.py`)

Events are grouped in a window (`CORRELATION_WINDOW_MINUTES`, default **240**) and linked when they share the employee, the session, an
unfamiliar address or a created account (an account created by an employee counts back to its creator). Each event maps to one of
eight **attack stages**: Initial Access, Credential Misuse, Sensitive Resource Access, Collection, Privilege Escalation, Persistence,
Lateral Movement, Exfiltration. Stages are derived from evidence **in any order**; no fixed sequence is required.

---

## 7. How attacks are prevented and responded to

### 7.1 Preventive controls that are always on

| Control | What it stops |
|---|---|
| Argon2id salted password hashes | a stolen database revealing passwords |
| Equal-time check for unknown IDs | learning which employee IDs exist by timing |
| Random session tokens; only an HMAC stored; 480-minute life; revocation | stolen database revealing live sessions; sessions that never end |
| Backend decides identity, address and device | an attacker choosing another ID or address in a request |
| Role-based access control (`security_admin` vs `employee`) | employees reaching SOC endpoints |
| Per-resource permission check on every access | reading or exporting data the role is not granted |
| Self-only profile endpoint | reading another employee's private record (IDOR) |
| Sign-in throttle (5 failures per ID, 300 s) and per-address limit; per-route limits (HTTP 429 with `Retry-After`) | online password guessing and scripted abuse |
| Export policy (below) | quiet mass data theft with a valid account |
| Input validation, size limits, safe error messages | malformed requests, stack-trace leaks |
| Idempotency keys | the same request being counted twice |
| Append-only evidence with SHA-256 | tampering with an investigation unnoticed |
| Audit log | actions without accountability |
| Production start-up checks | running with a weak secret, wildcard CORS, no secret source |

### 7.2 Bulk-export policy

Applied **before** anything is processed (in the resource-access endpoint, the payroll export and the document download):

| Request | Outcome |
|---|---|
| up to 10,000 records | allowed (subject to the hourly allowance) |
| over 10,000 in one request | **held (HTTP 409)**; a request is created for a security administrator; nothing is processed |
| over 100,000 in one request | **refused (HTTP 403)**; cannot be approved |
| hourly total over 25,000 per account | refused with HTTP 429 and `Retry-After` (staff with write access in the resource's own department get 5 times as much) |

Approvals are **single-use**, tied to that account, resource, action and size, expire after 60 minutes, and the requester can never
decide their own request. Repeated held requests raise the "repeated bulk-export requests" incident.

### 7.3 Automatic response policy

| Response | Detail |
|---|---|
| **Lock account** | 15 minutes; revokes all its sessions; the account cannot sign in until it expires or an administrator unlocks it |
| **Refuse address** | 60 minutes; the application's login code refuses it. **Not a firewall rule**, and does not stop traffic reaching the host |
| **Revoke sessions** | ends every active session of the account |
| **Never applied to** | security administrators (never auto-locked), private, loopback or protected addresses, or any employee's registered address |
| **Caps** | at most 10 automatic locks and 10 automatic address refusals per hour; further ones become *pending approval* for an analyst |
| **Detect-only mode** | `AUTH_AUTO_RESPONSE=false` records and alerts but does not act |

Every action records who or what did it (policy or analyst), when, why, the result and the expiry.

### 7.4 Analyst containment (Response Centre and investigation page)

Needs a security-administrator session, a written reason, and a confirmation for disruptive actions.

| Action | What changes (in this application's records only) |
|---|---|
| Disable account | account locked, sessions revoked, new logins refused |
| Revoke sessions | the employee's open sessions revoked |
| Block IP in this application | address added to the application's block list; its login code refuses it |
| Remove privileges | write permissions become read; on an account created during an incident, every permission is deleted |
| Restrict sensitive access | confidential and restricted permissions (or one chosen resource) deleted |
| Isolate system record | resource flagged isolated; the permission check denies everyone until released |
| Resolve investigation | investigation and its alerts marked resolved, with a reason |
| Restore account / unblock / release | undo the disruptive actions |

Safeguards: administrators cannot contain their own account; at most 30 containment requests per administrator per minute; an
`idempotency_key` makes a retry return the original action instead of acting twice; a request that would change nothing is refused
with 409. Events, evidence and risk assessments are never modified by containment (a test compares table digests before and after).

---

## 8. How the score works

An analyst sees **four different readings**. **None of them is a probability.** There are no labelled real-world incidents from which
a probability could be calibrated, so each number is a model output on its own scale or a hand-assigned weight, and the dashboards say so.

| Reading | Range | What it is |
|---|---|---|
| **Heuristic risk score** | 0 to 100 | hand-weighted evidence score used to rank activity |
| **Risk band** | Normal / Watch / Elevated / Alert | the score against calibrated thresholds, **limited by independent attack stages** |
| **Impact severity** | None / Low / Medium / High / Critical | what the evidence shows was accessed, exported or changed (never uses the score or the model) |
| **Evidence strength** | None / Weak / Moderate / Strong | how well independent evidence corroborates the finding |

### The formula (`backend/scoring.py`, `backend/threat_engine.py`)

```
risk_score = 100 x ( 0.80 x rule_evidence  +  0.20 x anomaly_score )
```

* **`rule_evidence`** (0 to 1) combines the rule weights with a *noisy-OR*:
  * An event counts as evidence **once**, through its strongest rule, however many times it appears.
  * Events with the same rule on the same target form one **group**, worth its strongest weight plus **25 %** of each further weight
    (`repeat_factor`), never more than **1.5 times** the strongest (`repeat_cap`).
  * Different groups combine as `1 - (1 - g1) x (1 - g2) x ...`, so many weak signals do **not** add up linearly.
* **`anomaly_score`** (0 to 1) comes from the Isolation Forest (plus the volume guard). It sees the same events as the rules, so its
  share is only 20 %, and it never raises the stage gate.
* **Not added to the score:** attack stage, correlation strength and baseline deviation. They are functions of the same rule evidence,
  and adding them would count one unfamiliar address or one large export four times. The independent-stage count **gates the band**
  instead of adding points.
* The whole-number score is floored so it never reads higher than the exact value.

### The band and the stage gate

* The **thresholds** come from `backend/operating_point.json`, chosen on validation runs (section 15): **Watch 37, Elevated 37, Alert 37**.
* **Stage gate:** the band implied by the score is lowered to **Watch** when fewer than **2** independent attack stages exist, and to
  **Elevated** when fewer than **3** exist. So **Alert needs a score of at least 37 *and* at least 3 independent stages.**
* Therefore one loud signal, however strong, cannot reach Alert alone. The investigation page shows both the band from the score alone
  and the final band.

| Band | Needs |
|---|---|
| Normal | score below 37 |
| Watch | score at or above 37 (also the ceiling when fewer than 2 stages exist) |
| Elevated | score at or above 37 and at least 2 independent stages |
| **Alert** | score at or above 37 and at least **3** independent stages. **An alert and an investigation are created here.** |

### Impact severity (rules over the evidence, not the score)

| Level | When |
|---|---|
| **Critical** | an external transfer is confirmed, or a foothold (persistence, lateral movement) exists next to a confirmed export |
| **High** | records potentially exposed reach the bulk threshold, or privileges were escalated |
| **Medium** | a confirmed export below bulk; suspicious access to sensitive records; credential misuse; sensitive-resource access; collection |
| **Low** | other suspicious activity |
| **None** | otherwise |

### Evidence strength

* **None**: no rule evidence.
* **Strong**: at least 3 independent stages, or 2 stages and the trained model agrees.
* **Moderate**: 2 stages, or 1 stage and the model agrees.
* **Weak**: otherwise.
* The model "agrees" only when a trained forest is loaded and its anomaly score reaches `ML_CORROBORATION_THRESHOLD` (0.45). The
  heuristic fallback never counts as corroboration.

### Severity is kept apart from certainty

A bulk export of 25,000 records with nothing else going on reports **High** impact, one attack stage, a **Watch** band and at most
Moderate evidence: serious if true, but uncertain whether it is an attack. A chain of weak signals can be the opposite: Alert band and
Strong evidence with only Low or Medium impact. The alert records all three readings separately.

### What an analyst can inspect for any score

The formula; each component with its value, weight and points (they add up to the score); each rule group with the weight counted,
the event references and first/last time; which events were considered and counted; the time window; the model output (mode, score,
raw score, volume guard); the feature deviations the model reacts to; the stage gate; the thresholds in force and where they came
from; and the reasons behind the impact and strength readings. (Investigation page: "How the heuristic risk score was built".)

### Authentication-defence severity

Path A incidents are **rule-based bands** (Watch / Elevated / Alert) from the count against the threshold. They are *not* scored by the
formula above and are not probabilities. Each incident states its rule, window, threshold and counted evidence.

---

## 9. How much one event moves the score, and why

Points below are the contribution **of that rule alone**, with the anomaly score at 0:
`points = 100 x 0.80 x weight`. The anomaly model can add up to **20 more points** (anomaly score 1.0 adds 20), so real scores are
slightly higher when behaviour is also statistically unusual. Rules below weight 0.10 are context only and add **0**.

| Rule | Weight | Points alone | Counts? | Why this weight |
|---|---|---|---|---|
| `failed_login` | 0.05 | 0 (context) | no | one typo is normal; the burst rule handles repetition |
| `access_denied` | 0.06 | 0 (context) | no | the permission system working as designed |
| `off_hours_login` | 0.08 | 0 (context) | no | many people work late; suppressed for regular late workers |
| `data_export` | 0.08 | 0 (context) | no | exports are routine; only unusual size matters |
| `sensitive_access_novel` | 0.12 | 9.6 | yes | unusual but permitted; weak on its own |
| `unfamiliar_ip` | 0.18 | 14.4 | yes | travel, new device or VPN are common; weak alone, strong in combination |
| `unauthorised_department_access` | 0.26 | 20.8 | yes | an attempt at another department's confidential data |
| `rapid_enumeration` | 0.30 | 24.0 | yes | touching 5+ classified resources in 10 minutes looks like harvesting |
| `restricted_denied` | 0.32 | 25.6 | yes | an attempt at a restricted resource that was refused |
| `removable_media_copy` | 0.34 | 27.2 | yes | copying classified records off the system; halved below the bulk threshold |
| `failed_login_burst` | 0.38 | 30.4 | yes | 3 failures in 10 minutes is guessing, not a typo |
| `login_after_failures` | 0.38 | 30.4 | yes | a success after failures: the guess may have worked |
| `unusual_outbound_transfer` | 0.38 | 30.4 | yes | a first-ever or very large external transfer |
| `permission_change_attempt` | 0.40 | 32.0 | yes | trying to widen access |
| `large_export` | 0.42 | 33.6 | yes | far above that employee's own history |
| `admin_console_login_failed` | 0.45 | 36.0 | yes | someone attacking the administrator console |
| `new_account_login` | 0.45 | 36.0 | yes | an account created in the last 24 hours is a classic foothold |
| `privileged_account_created` | 0.58 | 46.4 | yes | a persistence mechanism (scaled to 0.45 for routine IT work) |
| `external_transfer_confirmed` | 0.72 | 57.6 | yes | data actually left the organisation |

**Reading the table against the threshold (37):**
* **No single rule below weight about 0.46 can reach 37 alone** (0.4625 x 80 = 37), so ordinary oddities stay Normal.
* Even a rule that does reach 37 (`privileged_account_created` 46.4, `external_transfer_confirmed` 57.6) cannot become **Alert** alone: it
  counts toward one independent stage (each event counts toward one), so the stage gate holds the band at **Watch**.
* **Combinations are what raise the band**, and they raise it sub-linearly:

| Combination (anomaly score assumed 0) | Rule evidence | Score | What it means |
|---|---|---|---|
| `unfamiliar_ip` alone | 0.18 | 14.4 | Normal |
| `unfamiliar_ip` + `restricted_denied` | 1 - 0.82 x 0.68 = 0.442 | 35.4 | still below 37: Normal |
| `unfamiliar_ip` + `rapid_enumeration` + `large_export` | 1 - 0.82 x 0.70 x 0.58 = 0.667 | 53.4 | above 37; with 3 stages (Initial Access, Sensitive Resource Access, Collection) this is **Alert** |
| the compromised-account chain: `unfamiliar_ip` + `restricted_denied` + `large_export` + `failed_login_burst` + `privileged_account_created` | 0.916 | 73.3 | Alert, at least 5 independent stages |
| `large_export` happening twice | group = 0.42 + 0.25 x 0.42 = 0.525 | 42.0 | repeating the same evidence adds only 25 %, capped at 1.5 x 0.42 = 0.63 (50.4 points) |

These figures are exact from the formula. A real run adds the anomaly share (up to 20 points), so for example the project's documented
test run goes 33.1 (unfamiliar login) to 84.3 (restricted access, two stages) to 90.9 (large export, three stages: Alert), and then
higher as later steps arrive. Other times of day and seeds give other values.

---

## 10. When does the score go back to normal

**There is no gradual decay. The score is recomputed from a sliding window of recent events, so it falls as the evidence ages out.**

* **Insider score (path B).** The score for an employee is calculated from the events in the **last 240 minutes (4 hours)**
  (`CORRELATION_WINDOW_MINUTES`). When an event is older than the window it no longer counts, so the score steps down as each piece of
  evidence leaves the window. When **no events remain in the window**, the employee's assessment is idle: score 0, band Normal.
  The baseline for "normal" excludes the current window, so an attack never becomes the new normal.
* **Repeated bad behaviour keeps it up.** New suspicious events keep refreshing the window, so the score stays high while the activity continues.
* **Alerts and investigations do not close by themselves.** They stay until an analyst resolves them (reason required). The alert keeps
  its **peak score**, and the history of scores stays in the database. There is one active investigation per employee; after it is
  resolved, a later Alert-band alert opens a new one.
* **Account locks (path A)** expire automatically after **15 minutes** (an administrator can unlock sooner). The expiry is applied the
  next time the account is used or signs in; sessions revoked by the lock never come back, so the person must sign in again.
* **Address refusals** expire after **60 minutes** (an administrator can remove them sooner).
* **Detection windows** for path A are short (5, 10 or 30 minutes depending on the pattern), so once the window passes the counts fall
  and the pattern no longer fires. The incident record stays in the history, with its evidence.
* **Sign-in throttle:** five failures for one ID lock further attempts for **5 minutes** (in memory, lost on restart).
* **Held export approvals** expire after 60 minutes if unused; unanswered requests expire too.
* **Stored data:** sign-in attempts are kept for 30 days (`AUTH_ATTEMPT_RETENTION_DAYS`); events and evidence are not deleted.

**Practical example.** At 10:00 an account shows an unfamiliar address, restricted probing and a large export: score about 90, Alert,
investigation opened. The analyst locks the account and resolves the investigation at 10:20. If nothing else happens, the live score
reaches Normal at about **14:00** (the last event leaves the 4-hour window), while the alert, its peak score, the evidence and the
audit trail remain.

---

## 11. Investigations and evidence

An Alert-band alert creates **one investigation per employee**; every later related event updates it.

* **Case file:** sessions, suspicious addresses, related privileged accounts, first and latest suspicious event, risk score, band,
  impact severity, evidence strength, stage, sensitive resources accessed, records exported, potentially exposed, confirmed external transfers.
* **Status:** open, contained or resolved.
* **Preserved evidence:** related events are collected by employee, session, address, created account, resource and time and copied once
  into an **append-only** table with a **SHA-256** of the original. Every view and export compares each copy with the live event
  (`verified`, `modified`, `missing`).
* **Explanation:** a deterministic, rule-based write-up (no AI service, no network call): likely attack type, stage, suspicious activity,
  supporting evidence with real event IDs and times, the risk assessment, recommended containment, **missing evidence** and
  **alternative explanations**. It never names the person behind an account.
* **Classification:** possible insider misuse, compromised credentials, automated account exploitation, privilege escalation,
  unauthorised data export, confirmed external transfer: each reported as supported or not by the evidence.
* **Data exposure** is reported separately from the score, so a high score never implies that data was lost: sensitive records accessed,
  exported, potentially exposed, tied to external transfers, and whether an external transfer was *confirmed*.
* **Export:** a JSON or CSV evidence report per investigation.

---

## 12. The database

SQLite locally (safely configured for concurrent use, with limits documented), PostgreSQL for anything shared or deployed. Versioned
migrations create the schema; indexes cover the real query patterns (event time, employee, alert status, investigation).

| Table | Purpose |
|---|---|
| `employees` | accounts, role, department, registered addresses, hashed password, lock state |
| `employee_sessions` | sessions (token digest only), expiry, revocation |
| `access_permissions` | who may read or write which resource |
| `security_events` | every recorded action (type, resource, address, device, outcome, records, details) |
| `risk_assessments` | the stored score history with its explanation |
| `security_alerts` | alerts with band, impact, evidence strength, peak score and score basis |
| `attack_investigations` | one per employee, status and case file |
| `investigation_evidence` | append-only, hash-checked evidence copies |
| `containment_actions` | every containment action: who, when, why, result, records changed, idempotency key |
| `audit_logs` | administrator and system actions |
| `response_controls` | active address blocks and isolated systems |
| `auth_attempts` | every sign-in attempt (success, failure, refused); unknown names as a keyed hash |
| `access_denials` | every recorded `401` / `403` |
| `auth_incidents` | detected authentication, refusal and export incidents with evidence |
| `auth_response_actions` | automatic and manual responses (lock, unlock, revoke, block, unblock) |
| `export_requests` | held, approved, denied, used, expired and refused bulk-export requests |
| `ip_blocks` | address refusals with expiry |
| `simulation_runs` | history of the offline lab (kept so old data stays readable) |

Event ingestion and alert creation are transactional; a repeated request is stored once (idempotency key); incident creation uses a
unique key plus a savepoint so concurrent requests cannot create duplicates; approvals and locks use compare-and-set updates.

---

## 13. The API

Interactive documentation is at `/docs` in development (turned off in production). Roles: **public**, **any signed-in employee**,
**admin** (`security_admin`).

| Area | Key endpoints | Access |
|---|---|---|
| Health | `GET /api/health` | public |
| Authentication | `POST /api/auth/login`, `POST /api/auth/logout` | public / any |
| Profile | `GET /api/employees/me`, `GET /api/employees/{id}` | self or admin |
| Resources | `GET /api/resources`, `POST /api/resources/{id}/access` (view, download, export) | permitted employees |
| Portal | `/api/portal/profile`, `/payslips`, `/payroll/register`, `/payroll/export`, `/hr/records`, `/documents`, `/directory`, `/exports` | per resource |
| Events | `POST /api/events`, `GET /api/events/me`, `GET /api/events` | own / admin |
| Risk | `GET /api/risk/employees`, `POST /api/risk/assess` | admin |
| Alerts | `GET /api/alerts`, `PATCH /api/alerts/{id}` (filter by `risk_band` and `impact_severity`) | admin |
| Investigations | `/api/investigations`, `/explanation`, `/evidence`, `/export`, `/resolve` | admin |
| Containment | `GET/POST /api/containment` | admin |
| SOC read models | `/api/soc/overview`, `/events`, `/employees`, `/investigations`, `/timeline`, `/graph`, `/response`, `/audit` | admin |
| Authentication defence | `/api/soc/auth/overview`, `/incidents`, `/attempts`, `/denials`, `/actions`, `/export-requests`, `/export-requests/{id}/decision` | admin |
| System | `GET /api/system/database`, `/api/detection/status`, `/api/detection/reload`, `/api/detection/retrain` | admin |

Unauthenticated calls return `401`, wrong role `403`, invalid input `422`, too many requests `429`. The server never returns stack traces.

---

## 14. Security design

* **Passwords:** Argon2id with a per-password salt; older hashes are upgraded at login; no password is ever stored, logged or returned.
* **Sessions:** random tokens, only an HMAC is stored, 480-minute life, revocable, revoked automatically by locks.
* **Secrets:** read from the environment; production **refuses to start** without a strong `SECRET_KEY` (32+ characters), without demo
  credentials from a secret source, or with a wildcard CORS origin. Demo passwords are random, generated locally into a git-ignored
  file, and never stored in the repository.
* **Authorization on the backend:** every state-changing route checks the role on the server; hiding a button is never the only control.
* **Rate limits:** sign-in (per ID and per address), sensitive administrator routes, containment, heavy actions.
* **Client address trust:** a client-reported address is believed only with the shared `TRUSTED_FRONTEND_KEY`; the gateway overwrites
  anything a browser sends.
* **CORS** with explicit origins; **security headers**; request size limits; **HTTPS** is required in production (the deployment host
  provides it, the app does not).
* **No data leakage:** error responses carry no stack traces, secrets, file paths or database details.
* **Auditability:** logins, failures, account creation, response and failures are logged.
* **Isolation of the lab:** the offline simulator is refused in production and absent from the container image.

---

## 15. Machine learning and evaluation results

### The model

`IsolationForest` (300 trees), 10 features (section 6.4), trained on synthetic normal behaviour, saved to
`ml/artifacts/isolation_forest.joblib`, built automatically at start if missing and rebuilt by `POST /api/detection/retrain`.

### Measured on the project's own synthetic test set (839 windows)

| Metric | Value |
|---|---|
| ROC-AUC | 0.992 |
| False positives on all normal windows | 2.4 % |
| Attack recall, forest alone | 83.9 % (bulk export alone: 3.3 %, which is why the volume guard exists) |
| Attack recall, forest + volume guard | 100 % in every synthetic attack scenario |

These are optimistic, in-sample figures on data this project generated. They say nothing about real banks.

### Calibration of the thresholds (`python -m ml.calibrate_scoring`)

The eight seeded scenarios (two benign, six malicious) ran through the real pipeline: 96 runs on validation seeds, 96 on disjoint test
seeds. Thresholds were chosen on **validation only**; the result is recorded in `backend/operating_point.json`
(Watch 37, Elevated 37, Alert 37).

| Band | Malicious detected (test) | Benign flagged (test) |
|---|---|---|
| Watch | 67 of 72 (7 % missed) | 9 of 24 (38 %; all of them the benign lookalike for bulk export) |
| Elevated | 35 of 72 (51 % missed) | 0 of 24 |
| Alert | 23 of 72 (68 % missed) | 0 of 24 |

**The trade-off:** Alert flags no benign run but misses many malicious ones; Watch catches almost all malicious runs but flags many
benign large transfers. The labels are the generator's own and the test seeds come from the same generators, so these figures are optimistic.

### External benchmark: CERT Insider Threat Test Dataset r4.2

CERT r4.2 is **synthetic** (generated users and synthetic malicious actors), so no figure describes a real organisation. The data is not
in the repository. Held-out test users, threshold calibrated on validation users only:

| Detector | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Original approach (Isolation Forest on raw volumes) | 0.013 | 0.018 | 0.015 | 0.0040 |
| Isolation Forest on deviation features | 0.150 | 0.149 | 0.150 | 0.0024 |
| Hybrid (rules + correlation + anomaly model) | 0.170 | 0.229 | 0.195 | 0.0032 |
| Supervised reference (uses labels; a ceiling, not a deployable detector) | 0.291 | 0.993 | 0.450 | 0.0070 |

Bulk export (a separate synthetic report; CERT has no bulk-export scenario): the hybrid detected 6 of 7 incidents with **0 false alerts
on benign large transfers**. In the later rigorous evaluation (user-disjoint and time-ordered splits) the hybrid's window-level F1 on
CERT was **0.175**, still low precision, and it missed both scenario-3 incidents. Ground-truth labels are never used as model inputs
(a leakage test enforces it). Synthetic and CERT results are always reported separately.

---

## 16. Running it, demoing it, and the attack drill

### Run locally

```powershell
pip install -r requirements.txt
python app.py setup          # .env with random SECRET_KEY and TRUSTED_FRONTEND_KEY, random demo credentials (git-ignored)
python app.py credentials    # shows the demo sign-in passwords on this machine
python app.py all            # backend :8000, portal :8501, SOC :8503
```

Demo accounts (synthetic): `EMP-1001` Alice (Finance), `EMP-1002` Bob (Payroll), `EMP-1003` Carol (HR Manager), `EMP-1004` David (IT
Admin), `EMP-1005` Emma (Trading), `EMP-1006` Frank (Customer Service), `EMP-1007` Grace (Compliance), `EMP-1008` Henry (Engineering),
`EMP-1009` Isla (Lending), `EMP-1010` Jack (Marketing), and `SEC-9011` Sam (SOC administrator).

### The attack drill: real requests against the running backend

```powershell
python -m deploy.attack_drill brute-force           # 5 wrong passwords for EMP-1010 from an outside address
python -m deploy.attack_drill credential-stuffing   # one password against all accounts from one address
python -m deploy.attack_drill idor                  # EMP-1003 reads other employees' records one by one
python -m deploy.attack_drill bulk-export           # EMP-1001 asks for 15,000 records at once
python -m deploy.attack_drill compromised-account   # valid password from an unfamiliar address: probing, then big exports
python -m deploy.attack_drill recover               # unlock accounts and unblock addresses afterwards
```

Every call is an ordinary request to the real endpoints and every result is the backend's own answer. Outside addresses are RFC 5737
documentation addresses. `compromised-account` goes through the whole insider pipeline and raises an Alert and an investigation.

### Being the attacker from a second device

The portal treats a browser on this machine (`localhost`) as the employee's own workstation. To be someone else, open the portal through
the machine's network address from another device on the same Wi-Fi, for example `http://192.168.0.107:8501` (find yours with
`ipconfig`; use the IPv4 address). The portal reports that address to the backend, which sees one the account has never used. Five wrong
passwords for `EMP-1010` then lock the account and raise the incident on the SOC page, which you keep open as `SEC-9011`. If Windows asks,
allow Python on the network.

### Suggested demo order (about 10 minutes)

1. SOC dashboard, Authentication Defence: quiet.
2. Brute force on `EMP-1010` from the second device; refresh: locked account, incident, evidence, automatic response, expiry.
3. Unlock it in the SOC page with a reason; show the audit log.
4. `credential-stuffing` (address refused by the application), then `idor` (nothing returned, everything recorded) and `bulk-export` (HTTP 409,
   approve, single use).
5. `compromised-account`: Live Event Feed, Employee Risk Monitor, Attack Investigations; open the investigation; show the score breakdown
   and explain that the score is not a probability; **Run containment**; show the history and the audit entry.
6. `recover` to reset.

---

## 17. Deployment status

* **Nothing is deployed and there is no public URL.**
* A single-container design is prepared for Render (`Dockerfile`, `render.yaml`, `deploy/start.py`, `deploy/gateway.py`,
  `deploy/preflight.py`, `docs/deployment.md`): backend and both dashboards on loopback behind a gateway that is the only public port, the
  API never public, an administrator gate in front of the SOC dashboard, persistent PostgreSQL, secrets only from the host.
* It was rehearsed locally (embedded PostgreSQL, a clean-virtualenv install, a restart check). **The Docker image has never been built and
  Render has never been used.** Vercel cannot host this architecture (long-running processes, websockets, no durable filesystem).
* A real deployment needs your hosting account and database, a new migration (the current schema change was edited in place before any
  release), and re-running `python -m deploy.verify` against the live service.

---

## 18. Project structure and tests

```
app.py                 launcher (setup, credentials, backend, portal, soc, all)
backend/               FastAPI app, models, migrations, event pipeline, detection, scoring, correlation, auth defence,
                       export policy, investigations, containment, SOC read models, configuration
frontend/              employee_portal.py, soc_dashboard.py, soc_auth_defense.py, components, theme, api_client
ml/                    anomaly model, features, training, calibration, dataset evaluation, CERT pipeline, detector benchmark
data/                  seed data, demo accounts (credentials are generated locally, never committed)
deploy/                container start-up, gateway, preflight checks, verifier, attack drill
lab/                   offline scenario simulator (tests and calibration only; not in the image; refused in production)
tests/                 571 automated tests
docs/                  deployment guide, CERT dataset notes, detection evaluation
reports/               calibration and evaluation outputs
```

Tests cover: authentication and authorization, brute force, credential stuffing, refusal monitoring, IDOR probing, export approval
(including eight simultaneous uses of one approval), scoring ranges and explanations, containment idempotency and scope, persistence and
restart, concurrent ingestion and de-duplication, PostgreSQL, deployment files, the gateway, the Streamlit pages against a real
backend, the attack drill and the deployment verifier. `python -m pytest tests -q` runs them (several minutes: real backends are started).

---

## 19. Limits and honest caveats

* **Synthetic only.** Accounts, history and the CERT dataset are synthetic. No result describes a real organisation.
* **Thresholds are untuned starting values**, calibrated on synthetic runs. They are not validated against real traffic or real incidents.
* **Scores are heuristics, not probabilities.** A "high" band means "worth an analyst's time", not "this is an attack with probability X".
* **Enforcement is application-level.** An address block does not stop traffic reaching the host; there is no firewall, identity provider,
  email or endpoint integration.
* **Precision is low on CERT** (hybrid window-level F1 0.175) and the bulk-export figures come from a project-generated synthetic set.
* **Detection needs events.** An attacker who never touches the application produces nothing to analyse.
* **In-memory limits:** the sign-in throttle and rate limiters live in one process (run a single backend worker); they reset on restart.
* **Concurrency was tested on SQLite**, not on PostgreSQL with several instances.
* **Locally, a browser on this machine looks like the employee's own workstation**, so wrong passwords typed on `localhost` are recorded
  but are not an attack; use another device or the drill.
* **Not built yet:** firewall integration, Redis, password-change and geolocation detections, progressive login delays, analyst
  assignment, a portal page for employees to track their own export requests, a Next.js front end, calibration on real traffic, a public
  deployment.
* **Do not describe it as** production-ready, banking-grade, or able to block real attacks.

---

## 20. Glossary

| Term | Meaning |
|---|---|
| **SOC** | Security Operations Centre: the team (and dashboard) that watches for attacks |
| **Brute force** | guessing many passwords for one account |
| **Credential stuffing** | trying one (often leaked) password across many accounts |
| **IDOR** | asking for other people's records by changing an identifier in a request |
| **Insider threat** | an employee, or a compromised employee account, misusing legitimate access |
| **Event** | one recorded action (sign-in, access, download, export, transfer) |
| **Rule weight** | hand-assigned 0 to 1 strength of a rule as evidence; not a probability |
| **Anomaly score** | 0 to 1 output of the Isolation Forest: how unusual the behaviour is compared with normal |
| **Heuristic risk score** | the 0 to 100 combination of rule evidence and anomaly score |
| **Risk band** | Normal / Watch / Elevated / Alert: the score against the threshold, limited by attack stages |
| **Impact severity** | how serious the evidence shows the consequence to be, independent of how sure the detector is |
| **Evidence strength** | how well independent evidence supports the finding |
| **Attack stage** | one of eight phases (Initial Access ... Exfiltration) an event can support |
| **Independent stage** | a distinct attack stage with rule evidence; the number of them gates the band |
| **Correlation window** | the 240-minute window of recent events used for scoring |
| **Baseline** | an employee's own normal behaviour over the previous 30 days |
| **Containment** | an action that limits a suspected incident (lock, revoke, refuse, restrict) |
| **Idempotent** | repeating the same request does not repeat the action |
| **Operating point** | the chosen thresholds and the trade-off between missed detections and false alarms |
| **Synthetic** | generated for the project; not real people or data |
