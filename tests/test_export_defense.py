"""Bulk export and download authorization, tested with real requests: the policy decides on the server before any data is
processed (size limits, single-use security approval, hourly allowance), and repeated attempts become an incident."""
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from conftest import auth_header, run_scenario
from test_auth_defense import KNOWN, bearer, db_read, incidents, signin, status_of

from backend import export_policy
from backend.database import SessionLocal, engine, utcnow
from backend.models import Employee, ExportRequest

FIN, CUST, PAYROLL = "financial-reports", "customer-accounts", "payroll-records"


def pks(client, admin) -> dict[str, int]:
    return {e["employee_code"]: e["id"] for e in client.get("/api/employees", headers=admin).json()}


def take(client, token, resource, records, action="export", approval_id=None):
    body = {"action": action, "record_count": records, **({"approval_id": approval_id} if approval_id else {})}
    return client.post(f"/api/resources/{resource}/access", headers=token, json=body)


def alice(client):
    return bearer(signin(client, "EMP-1001", None, KNOWN["EMP-1001"]))


def bob(client):
    return bearer(signin(client, "EMP-1002", None, KNOWN["EMP-1002"]))


def requests_of(client, admin, status="all") -> list[dict]:
    return client.get("/api/soc/auth/export-requests", headers=admin, params={"status": status}).json()["rows"]


def decide(client, admin, request_id, decision="approve", note="Reviewed with the data owner", **extra):
    return client.post(f"/api/soc/auth/export-requests/{request_id}/decision", headers=admin,
                       json={"decision": decision, "note": note, **extra})


def events_of(client, admin, employee_pk, event_type):
    return client.get("/api/events", headers=admin, params={"employee_id": employee_pk, "event_type": event_type, "limit": 50}).json()["items"]


# ------------------------------------------------------------------------------------------------- the normal case
def test_normal_sized_exports_and_downloads_are_unaffected(client, admin):
    token = alice(client)
    done = take(client, token, FIN, 500)
    assert done.status_code == 200 and done.json()["record_count"] == 500
    assert take(client, token, CUST, 100, action="download").status_code == 200
    assert take(client, token, FIN, 0, action="view").status_code == 200
    assert requests_of(client, admin) == []


# ------------------------------------------------------------------------------------------------------- approval
def test_a_bulk_export_is_held_for_approval_before_anything_is_processed(client, admin):
    ids = pks(client, admin)
    held = take(client, alice(client), FIN, 10_001)
    assert held.status_code == 409 and "approval" in held.json()["detail"] and "records" not in held.json()
    (request,) = requests_of(client, admin, "pending")
    assert request["employee_id"] == "EMP-1001" and request["records"] == 10_001 and request["reason"] == "approval_required"
    assert request["resource"] == FIN and request["status_label"] == "Awaiting approval" and f"approval_id={request['id']}" in held.json()["detail"]
    exports = events_of(client, admin, ids["EMP-1001"], "data_export")
    assert exports[0]["outcome"] == "denied" and exports[0]["records_downloaded"] == 0 and exports[0]["details"]["reason"] == "export_requires_approval"
    assert exports[0]["details"]["export_request_id"] == request["id"]


def test_an_approval_is_single_use_and_the_export_then_proceeds_and_is_recorded(client, admin):
    ids = pks(client, admin)
    token = alice(client)
    take(client, token, FIN, 12_000)
    (request,) = requests_of(client, admin, "pending")
    approved = decide(client, admin, request["id"], valid_minutes=30)
    assert approved.status_code == 200 and approved.json()["status"] == "approved" and approved.json()["decided_by"] == "SEC-9011"
    assert approved.json()["expires_at"]["utc"]

    done = take(client, token, FIN, 12_000, approval_id=request["id"])
    assert done.status_code == 200 and done.json()["record_count"] == 12_000
    assert requests_of(client, admin, "used")[0]["id"] == request["id"]
    exports = events_of(client, admin, ids["EMP-1001"], "data_export")
    assert exports[0]["outcome"] == "success" and exports[0]["records_downloaded"] == 12_000 and exports[0]["details"]["export_approval_id"] == request["id"]

    again = take(client, token, FIN, 12_000, approval_id=request["id"])                       # the approval is spent
    assert again.status_code == 409 and "not valid for this request" in again.json()["detail"]
    audit = {r["action"] for r in client.get("/api/soc/audit", headers=admin, params={"limit": 500}).json()["rows"]}
    assert "export_approved" in audit


def test_an_approval_covers_only_its_account_resource_action_and_size(client, admin):
    token, other = alice(client), bob(client)
    take(client, token, FIN, 20_000)
    (request,) = requests_of(client, admin, "pending")
    decide(client, admin, request["id"])
    assert take(client, other, PAYROLL, 20_000, approval_id=request["id"]).status_code == 409               # another account
    assert take(client, token, CUST, 20_000, action="download", approval_id=request["id"]).status_code == 409  # another resource and action
    assert take(client, token, FIN, 30_000, approval_id=request["id"]).status_code == 409                    # a bigger export
    assert [r["status"] for r in requests_of(client, admin) if r["id"] == request["id"]] == ["approved"]    # still unspent
    assert take(client, token, FIN, 15_000, approval_id=request["id"]).status_code == 200                   # a smaller one is covered
    assert take(client, token, FIN, 15_000, approval_id=request["id"]).status_code == 409


def test_a_denied_or_expired_request_cannot_be_used(client, admin):
    token = alice(client)
    take(client, token, FIN, 11_000)
    (first,) = requests_of(client, admin, "pending")
    assert decide(client, admin, first["id"], "deny", "Not justified for this role").json()["status"] == "denied"
    assert take(client, token, FIN, 11_000, approval_id=first["id"]).status_code == 409

    take(client, token, FIN, 11_000)
    second = next(r for r in requests_of(client, admin, "pending"))
    decide(client, admin, second["id"])
    con = sqlite3.connect(engine.url.database)
    con.execute("update export_requests set expires_at = ? where id = ?", ((utcnow() - timedelta(minutes=1)).isoformat(sep=" "), second["id"]))
    con.commit()
    con.close()
    assert take(client, token, FIN, 11_000, approval_id=second["id"]).status_code == 409
    assert [r["status"] for r in requests_of(client, admin) if r["id"] == second["id"]] == ["expired"]


def test_an_approval_can_be_spent_only_once_even_when_used_at_the_same_moment(client, admin):
    token = alice(client)
    take(client, token, FIN, 13_000)
    (request,) = requests_of(client, admin, "pending")
    decide(client, admin, request["id"])
    barrier = threading.Barrier(8)

    def spend(_):
        with SessionLocal() as db:
            employee = db.query(Employee).filter(Employee.employee_code == "EMP-1001").one()
            barrier.wait()
            won = export_policy._claim_approval(db, employee, FIN, "export", 13_000, request["id"])
            db.commit()
            return won

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(spend, range(8)))
    assert results.count(True) == 1


def test_deciding_is_validated_authorised_and_cannot_be_done_on_ones_own_request(client, admin):
    employee = auth_header(client, "EMP-1003")
    take(client, alice(client), FIN, 10_500)
    (request,) = requests_of(client, admin, "pending")
    path = f"/api/soc/auth/export-requests/{request['id']}/decision"
    assert client.post(path, json={"decision": "approve", "note": "valid note"}).status_code == 401
    assert client.post(path, headers=employee, json={"decision": "approve", "note": "valid note"}).status_code == 403
    assert client.get("/api/soc/auth/export-requests", headers=employee).status_code == 403
    for bad in ({"decision": "maybe", "note": "valid note"}, {"decision": "approve", "note": "no"}, {"decision": "approve", "note": "x" * 301},
                {"decision": "approve", "note": "valid note", "valid_minutes": 0}, {"decision": "approve", "note": "valid note", "valid_minutes": 5000}):
        assert client.post(path, headers=admin, json=bad).status_code == 422, bad
    assert client.post("/api/soc/auth/export-requests/999999/decision", headers=admin, json={"decision": "approve", "note": "valid note"}).status_code == 404
    assert client.get("/api/soc/auth/export-requests", headers=admin, params={"status": "bogus"}).status_code == 422
    assert decide(client, admin, request["id"]).status_code == 200
    assert decide(client, admin, request["id"], "deny", "changed my mind").status_code == 409              # already decided

    with SessionLocal() as db:                                                                              # the administrator's own request
        admin_pk = db.query(Employee).filter(Employee.employee_code == "SEC-9011").one().id
        mine = ExportRequest(employee_id=admin_pk, resource="audit-reports", action="export", records=50_000, status="pending",
                             reason="approval_required", source_ip="10.20.10.5", expires_at=utcnow() + timedelta(hours=1))
        db.add(mine)
        db.commit()
        own_id = mine.id
    assert decide(client, admin, own_id).status_code == 422


# ----------------------------------------------------------------------------------------------- hard and hourly limits
def test_a_request_above_the_absolute_limit_is_refused_and_cannot_be_approved(client, admin):
    refused = take(client, alice(client), FIN, 100_001)
    assert refused.status_code == 403 and "No approval can lift this limit" in refused.json()["detail"]
    (request,) = requests_of(client, admin, "refused")
    assert request["reason"] == "over_hard_limit" and request["status_label"] == "Refused (limit)"
    assert requests_of(client, admin, "pending") == [] and decide(client, admin, request["id"]).status_code == 409


def test_the_hourly_allowance_is_enforced_and_staff_who_own_the_data_get_more(client, admin, monkeypatch):
    monkeypatch.setenv("EXPORT_APPROVAL_THRESHOLD", "1000")
    monkeypatch.setenv("EXPORT_HOURLY_LIMIT", "300")
    monkeypatch.setenv("EXPORT_OWNER_MULTIPLIER", "1")
    token = alice(client)
    assert take(client, token, CUST, 250, action="download").status_code == 200            # not her department's data: base allowance
    over = take(client, token, CUST, 100, action="download")
    assert over.status_code == 429 and int(over.headers["Retry-After"]) >= 60 and "Export limit reached" in over.json()["detail"]
    assert [r["reason"] for r in requests_of(client, admin, "refused")] == ["hourly_limit"]

    monkeypatch.setenv("EXPORT_OWNER_MULTIPLIER", "5")                  # owner of financial reports: 1,500 per hour, across everything taken
    assert take(client, token, FIN, 800).status_code == 200 and take(client, token, FIN, 400).status_code == 200      # 250 + 800 + 400
    assert take(client, token, FIN, 200).status_code == 429                                                          # 1,650 > 1,500


def test_an_approved_request_bypasses_the_hourly_allowance_but_not_the_absolute_limit(client, admin, monkeypatch):
    monkeypatch.setenv("EXPORT_APPROVAL_THRESHOLD", "1000")
    monkeypatch.setenv("EXPORT_HOURLY_LIMIT", "300")
    monkeypatch.setenv("EXPORT_OWNER_MULTIPLIER", "1")
    token = alice(client)
    take(client, token, FIN, 5000)
    (request,) = requests_of(client, admin, "pending")
    decide(client, admin, request["id"])
    assert take(client, token, FIN, 5000, approval_id=request["id"]).status_code == 200


def test_exports_by_the_simulation_are_exempt_because_they_never_touch_real_data(client, admin):
    run_scenario(client, admin, "bulk_export", seed=3)
    assert requests_of(client, admin) == []


# ------------------------------------------------------------------------------------------------- detection and response
def test_repeated_bulk_requests_raise_an_incident_and_an_extreme_pattern_ends_the_session_and_locks_the_account(client, admin):
    token = alice(client)
    for _ in range(3):
        assert take(client, token, FIN, 20_000).status_code == 409
    (incident,) = [i for i in incidents(client, admin) if i["kind"] == "bulk_export_attempt"]
    assert incident["severity"] == "high_risk" and incident["employee_id"] == "EMP-1001" and status_of("EMP-1001") == "active"
    detail = client.get(f"/api/soc/auth/incidents/{incident['id']}", headers=admin).json()
    assert detail["evidence"]["attempts"] == 3 and detail["evidence"]["resources"] == [FIN] and len(detail["export_requests"]) == 3
    assert "before any data was processed" in detail["explanation"]

    for _ in range(3):
        take(client, token, FIN, 20_000)
    (incident,) = [i for i in incidents(client, admin) if i["kind"] == "bulk_export_attempt"]
    assert incident["severity"] == "critical" and status_of("EMP-1001") == "locked"
    assert client.get("/api/employees/me", headers=token).status_code == 401


def test_a_few_held_requests_and_decided_ones_do_not_raise_an_incident(client, admin):
    token = alice(client)
    take(client, token, FIN, 20_000)
    take(client, token, FIN, 20_000)
    assert [i for i in incidents(client, admin) if i["kind"] == "bulk_export_attempt"] == []


# --------------------------------------------------------------------------------------------- other export paths
def test_the_payroll_export_goes_through_the_same_policy(client, admin, monkeypatch):
    monkeypatch.setenv("EXPORT_APPROVAL_THRESHOLD", "5")
    token = bob(client)
    held = client.post("/api/portal/payroll/export", headers=token)
    assert held.status_code == 409 and "approval" in held.json()["detail"]
    (request,) = requests_of(client, admin, "pending")
    assert request["resource"] == PAYROLL and request["records"] >= 10
    decide(client, admin, request["id"])
    done = client.post("/api/portal/payroll/export", headers=token, params={"approval_id": request["id"]})
    assert done.status_code == 200 and done.json()["media_type"] == "text/csv" and done.json()["record_count"] == request["records"]


def test_employees_see_only_their_own_export_requests(client, admin):
    take(client, alice(client), FIN, 10_500)
    mine = client.get("/api/portal/exports", headers=alice(client)).json()
    assert [r["records"] for r in mine] == [10_500] and mine[0]["status"] == "pending"
    assert client.get("/api/portal/exports", headers=bob(client)).json() == []
    assert client.get("/api/portal/exports").status_code == 401


def test_pending_requests_nobody_decides_expire(client, admin):
    take(client, alice(client), FIN, 10_500)
    (request,) = requests_of(client, admin, "pending")
    con = sqlite3.connect(engine.url.database)
    con.execute("update export_requests set expires_at = ? where id = ?", ((utcnow() - timedelta(minutes=1)).isoformat(sep=" "), request["id"]))
    con.commit()
    con.close()
    assert requests_of(client, admin, "pending") == [] and requests_of(client, admin, "expired")[0]["id"] == request["id"]
    assert db_read(lambda db: db.query(ExportRequest).count()) == 1
