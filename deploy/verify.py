"""Smoke test of a running deployment. Run it against the real public URL once the service is live (and against a local run).

    # public checks, from anywhere (HTTP only; the API is private by design)
    python -m deploy.verify --url https://your-service.onrender.com --gate-user U --gate-password P

    # behaviour checks, run where the backend answers (the host's shell, or a local stack): sign-in, roles, ingestion,
    # de-duplication, detection, investigation, simulated containment, persistence
    python -m deploy.verify --url ... --api http://127.0.0.1:8000 --employee-password E --admin-password A [--snapshot s.json]
    # ...restart the service, then:
    python -m deploy.verify --api http://127.0.0.1:8000 --admin-password A --compare s.json

Secrets are read from arguments or the VERIFY_* environment variables and are never printed. Every check prints PASS or FAIL
with what was observed; the exit code is non-zero if any check failed. Behaviour checks create synthetic events and one synthetic
scenario run, and clean up after themselves (simulation reset, account restore).
"""
import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

import requests

SESSION = requests.Session()
RESULTS: list[tuple[bool, str]] = []


def check(ok: bool, name: str, detail: str = "") -> bool:
    RESULTS.append((bool(ok), name))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
    return bool(ok)


def basic(user: str | None, password: str | None):
    return (user, password) if user and password else None


# --------------------------------------------------------------------------------------------------------- public checks
def public_checks(url: str, gate_user: str | None, gate_password: str | None, forbidden: list[str]) -> None:
    url = url.rstrip("/")
    health = SESSION.get(f"{url}/healthz", timeout=30)
    body = health.json() if health.headers.get("content-type", "").startswith("application/json") else {}
    check(health.status_code == 200 and body.get("status") == "ok", "healthz: backend and all three dashboards are up", str(body.get("components")))

    home = SESSION.get(f"{url}/", timeout=30)
    check(home.status_code == 200 and "streamlit" in home.text.lower(), "the employee portal loads without any local connection")
    check(SESSION.get(f"{url}/api/health", timeout=30).status_code == 404 and SESSION.get(f"{url}/docs", timeout=30).status_code == 404,
          "the backend API and its docs are not reachable from the internet")
    check(home.headers.get("x-content-type-options") == "nosniff" and "x-frame-options" in home.headers, "security headers are present")
    if url.startswith("https://"):
        check(home.headers.get("strict-transport-security") is not None, "HSTS is sent over HTTPS")
        plain = SESSION.get("http://" + url[len("https://"):] + "/", timeout=30, allow_redirects=False)
        check(plain.status_code in (301, 302, 307, 308) and plain.headers.get("location", "").startswith("https://"),
              "plain HTTP is redirected to HTTPS", str(plain.status_code))

    for path, name in (("/soc/", "SOC dashboard"), ("/console/", "simulation console")):
        # a fresh request each time: the gate sets a cookie after a successful login, and a visitor has none
        denied = requests.get(f"{url}{path}", timeout=30)
        check(denied.status_code == 401 and "www-authenticate" in denied.headers, f"{name} refuses visitors without the administrator gate")
        wrong = requests.get(f"{url}{path}", auth=("nobody", "wrong-password-0000"), timeout=30)
        check(wrong.status_code == 401, f"{name} refuses wrong gate credentials")
        if gate_user and gate_password:
            ok = requests.get(f"{url}{path}", auth=basic(gate_user, gate_password), timeout=30)
            check(ok.status_code == 200 and "streamlit" in ok.text.lower(), f"{name} loads with the gate credentials")

    try:
        from websockets.sync.client import connect

        with connect(url.replace("http", "ws", 1) + "/_stcore/stream", origin=url, open_timeout=15,
                     additional_headers={"X-Forwarded-Proto": "https"} if url.startswith("https") else None) as ws:
            check(True, "the portal's websocket connects through the public address", ws.subprotocol or "")
    except Exception as exc:  # noqa: BLE001
        check(False, "the portal's websocket connects through the public address", type(exc).__name__)

    leaked = [name for name, value in forbidden if value and (value in home.text or value in json.dumps(dict(home.headers)))]
    check(not leaked, "no configured secret appears in the public pages or headers", ", ".join(leaked))


# --------------------------------------------------------------------------------------------------------- behaviour checks
def login(api: str, who: str, password: str) -> dict:
    r = SESSION.post(f"{api}/api/auth/login", json={"employee_id": who, "password": password}, timeout=30)
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def get(api: str, headers: dict, path: str, **params):
    r = SESSION.get(f"{api}{path}", headers=headers, params=params, timeout=60)
    r.raise_for_status()
    return r.json()


def behaviour_checks(api: str, employee_password: str, admin_password: str, snapshot: Path | None) -> None:
    api = api.rstrip("/")
    wrong = SESSION.post(f"{api}/api/auth/login", json={"employee_id": "EMP-1001", "password": "not-the-password-0000"}, timeout=30)
    check(wrong.status_code == 401, "a wrong password is refused")
    employee, admin = login(api, "EMP-1001", employee_password), login(api, "SEC-9011", admin_password)
    check(True, "the employee and the security administrator can sign in")
    check(SESSION.get(f"{api}/api/soc/overview", headers=employee, timeout=30).status_code == 403
          and SESSION.get(f"{api}/api/employees", headers=employee, timeout=30).status_code == 403, "an employee is refused every administrator endpoint")
    check(SESSION.get(f"{api}/api/soc/overview", timeout=30).status_code == 401, "a request without a session is refused")

    marker = f"verify-{uuid.uuid4().hex[:16]}"
    before = get(api, admin, "/api/soc/events", employee="EMP-1001", limit=1)["latest_id"]
    posts = [SESSION.post(f"{api}/api/events", headers={**employee, "Idempotency-Key": marker}, timeout=30,
                          json={"event_type": "resource_access", "resource": "my-profile", "record_count": 1}) for _ in range(3)]
    ids = {p.json()["event"]["id"] for p in posts if p.status_code == 201}
    feed = [r for r in get(api, admin, "/api/soc/events", employee="EMP-1001", limit=50)["rows"] if r["id"] > before]
    check(len(ids) == 1 and len(feed) == 1, "a synthetic event is ingested once and appears in the SOC feed; a retry with the same key adds nothing",
          f"stored {len(feed)}")
    marker_event = next(iter(ids), None)

    overview = get(api, admin, "/api/soc/overview")
    stats = get(api, admin, "/api/dashboard/stats")
    check(overview["kpis"]["total_events"] <= stats["events_total"] and overview["kpis"]["total_events"] > 0,
          "the SOC overview and the dashboard statistics read the same database")

    run = SESSION.post(f"{api}/api/simulation/runs", headers=admin, timeout=30,
                       json={"scenario": "compromised_account_campaign", "seed": 1, "pace": "instant"})
    if run.status_code != 202:
        check(False, "a synthetic attack scenario starts", f"{run.status_code} {run.text[:120]}")
        return
    run_id, target = run.json()["id"], run.json()["target"]["id"]
    for _ in range(240):
        state = get(api, admin, f"/api/simulation/runs/{run_id}")
        if state["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.5)
    check(state["status"] == "completed", "the synthetic attack scenario runs through the normal ingestion path", state["status"])
    alerts = [a for a in get(api, admin, "/api/alerts", employee_id=target) if a["status"] in ("open", "investigating")]
    check(bool(alerts), "detection raises an alert for the scenario that warrants one",
          f"risk band {alerts[0]['risk_band']}, impact {alerts[0]['impact_severity']}, evidence {alerts[0]['evidence_strength']}" if alerts else "no alert")
    invs = [i for i in get(api, admin, "/api/soc/investigations", status="active") if i["employee_pk"] == target]
    check(bool(invs), "an investigation exists with preserved evidence")
    if invs:
        detail = get(api, admin, f"/api/soc/investigations/{invs[0]['id']}")
        check(bool(detail["timeline"]) and detail["integrity"]["intact"], "the investigation's evidence is intact", f"{len(detail['timeline'])} events")
        key = uuid.uuid4().hex
        body = {"employee_id": target, "action_type": "lock_account", "reason": "Deployment verification drill", "confirm": True,
                "investigation_id": invs[0]["id"], "idempotency_key": key}
        first = SESSION.post(f"{api}/api/containment", headers=admin, json=body, timeout=30)
        again = SESSION.post(f"{api}/api/containment", headers=admin, json=body, timeout=30)
        record = first.json() if first.status_code in (200, 201) else {}
        check(first.status_code == 201 and again.status_code == 200 and again.json().get("id") == record.get("id"),
              "simulated containment completes once and a retry replays it", f"{first.status_code}/{again.status_code}")
        check(record.get("simulated") is True and not record.get("external_systems_contacted"),
              "the containment record says it only changed this application's own state")
        locked = next(e for e in get(api, admin, "/api/employees") if e["id"] == target)["status"] == "locked"
        check(locked, "the simulated account lock took effect inside the application")
        SESSION.post(f"{api}/api/containment", headers=admin, timeout=30,
                     json={"employee_id": target, "action_type": "restore_account", "reason": "Verification clean-up", "confirm": True})
    SESSION.post(f"{api}/api/simulation/reset", headers=admin, timeout=60)

    if snapshot is not None:
        stored = get(api, admin, "/api/system/database")
        snapshot.write_text(json.dumps({"marker_event": marker_event, "employee_pk": next(e["id"] for e in get(api, admin, "/api/employees")
                                                                                          if e["employee_code"] == "EMP-1001"),
                                        "row_counts": stored["row_counts"], "dialect": stored["dialect"]}), encoding="utf-8")
        print(f"      snapshot written to {snapshot}; restart the service, then run with --compare {snapshot}")


def compare_checks(api: str, admin_password: str, snapshot: Path) -> None:
    api = api.rstrip("/")
    before = json.loads(snapshot.read_text(encoding="utf-8"))
    admin = login(api, "SEC-9011", admin_password)
    info = get(api, admin, "/api/system/database")
    check(info["dialect"] == before["dialect"] and info["persistent_shared_store"] is (before["dialect"] != "sqlite"),
          "the same kind of database is in use after the restart", info["dialect"])
    counts = info["row_counts"]
    check(all(counts[k] >= v for k, v in before["row_counts"].items()), "no table has fewer rows than before the restart", str(counts))
    events = get(api, admin, "/api/events", employee_id=before["employee_pk"], limit=500)["items"]
    check(any(e["id"] == before["marker_event"] for e in events), "the event ingested before the restart is still stored")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m deploy.verify", description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", help="public address of the deployment (public checks)")
    parser.add_argument("--api", help="backend address reachable from where this runs (behaviour checks)")
    parser.add_argument("--gate-user", default=os.getenv("VERIFY_GATE_USER"))
    parser.add_argument("--gate-password", default=os.getenv("VERIFY_GATE_PASSWORD"))
    parser.add_argument("--employee-password", default=os.getenv("VERIFY_EMPLOYEE_PASSWORD"), help="password of EMP-1001")
    parser.add_argument("--admin-password", default=os.getenv("VERIFY_ADMIN_PASSWORD"), help="password of SEC-9011")
    parser.add_argument("--snapshot", type=Path, help="write a snapshot for the persistence check")
    parser.add_argument("--compare", type=Path, help="compare against a snapshot taken before a restart")
    args = parser.parse_args(argv)
    if not (args.url or args.api):
        parser.error("give --url, --api or both")

    forbidden = [(n, os.getenv(n, "")) for n in ("SECRET_KEY", "ADMIN_UI_PASSWORD", "DEMO_PASSWORDS_JSON", "DATABASE_URL")]
    forbidden += [("--gate-password", args.gate_password or ""), ("--admin-password", args.admin_password or ""),
                  ("--employee-password", args.employee_password or "")]
    if args.url:
        public_checks(args.url, args.gate_user, args.gate_password, [(n, v) for n, v in forbidden if len(v) >= 8])
    if args.api and args.compare:
        if not args.admin_password:
            parser.error("--compare needs --admin-password")
        compare_checks(args.api, args.admin_password, args.compare)
    elif args.api:
        if not (args.employee_password and args.admin_password):
            parser.error("behaviour checks need --employee-password and --admin-password")
        behaviour_checks(args.api, args.employee_password, args.admin_password, args.snapshot)
    failed = [name for ok, name in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
