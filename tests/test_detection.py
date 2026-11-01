"""Detection pipeline tests. Events go through the real application pipeline (record_event / authenticate /
simulation endpoints); nothing here computes scores independently of the backend."""
from datetime import datetime, time, timezone

import pytest
from conftest import auth_header
from sqlalchemy import select

from backend.auth_service import authenticate
from backend.config import get_settings
from backend.database import SessionLocal
from backend.errors import ServiceError
from backend.event_service import access_resource, record_event
from backend.models import Employee, SecurityEvent
from data.demo_accounts import demo_password

ATTACKER_IP = "185.220.101.45"
STEPS = ["unfamiliar_login", "restricted_access", "large_export", "admin_login_failures",
         "create_privileged_account", "privileged_login", "external_transfer"]


@pytest.fixture(autouse=True)
def clean_simulation(client, admin):
    yield
    client.post("/api/simulation/reset", headers=admin)


def employee(db, username):
    return db.scalar(select(Employee).where(Employee.username == username))


def risk(client, admin, username):
    with SessionLocal() as db:
        emp_id = employee(db, username).id
    return client.get(f"/api/risk/employees/{emp_id}", headers=admin).json()


def alerts_for(client, admin, username):
    with SessionLocal() as db:
        emp_id = employee(db, username).id
    return client.get("/api/alerts", headers=admin, params={"employee_id": emp_id}).json()


def synthetic_event(db, emp, event_type, *, ip, **kwargs):
    return record_event(db, emp, event_type, source_ip=ip, is_synthetic=True, scenario="detection_test", **kwargs)


def local_today_at(hour: int) -> datetime:
    tz = get_settings().tz
    local = datetime.combine(datetime.now(tz).date(), time(hour), tzinfo=tz)
    return local.astimezone(timezone.utc)


def rules_seen(data):
    return {f["rule"] for f in data["factors"]}


# ---------------------------------------------------------------- 1. normal activity
def test_normal_employee_activity_keeps_low_risk(client, admin):
    from ml.anomaly_detector import get_detector

    assert get_detector().available  # the saved Isolation Forest is in use, not the fallback
    jack = auth_header(client, "EMP-1010")
    for _ in range(2):
        assert client.get("/api/portal/payslips", headers=jack).status_code == 200
        assert client.get("/api/portal/documents", headers=jack).status_code == 200
        assert client.get("/api/portal/documents/DOC-010/download", headers=jack).status_code == 200
        assert client.get("/api/portal/directory", headers=jack, params={"q": "a"}).status_code == 200
        assert client.post("/api/resources/marketing-assets/access", headers=jack, json={"record_count": 4}).status_code == 200
    data = risk(client, admin, "jack.silva")
    assert data["level"] == "normal" and data["confidence"] < 25
    assert data["ml"]["mode"] == "isolation_forest" and data["current_stage"] == "none"
    assert data["exposure"]["status"] == "none"
    assert alerts_for(client, admin, "jack.silva") == []


# ---------------------------------------------------------------- 2. unfamiliar IP
def test_unfamiliar_ip_login_is_not_an_attack_by_itself(client, admin):
    with SessionLocal() as db:
        authenticate(db, "EMP-1009", demo_password("EMP-1009"), ip="203.0.113.9", synthetic=True,
                     scenario="detection_test")
    data = risk(client, admin, "isla.murphy")
    assert "unfamiliar_ip" in rules_seen(data)
    assert data["current_stage"] == "initial_access" and data["independent_stages"] == 1
    assert data["confidence"] < 50 and data["level"] in ("normal", "suspicious")
    assert alerts_for(client, admin, "isla.murphy") == []


# ---------------------------------------------------------------- 3. restricted resource access
def test_restricted_resource_access_is_sensitive_resource_access(client, admin):
    with SessionLocal() as db:
        jack = employee(db, "jack.silva")
        for resource in ("hr-records", "payroll-records"):
            _, permitted = access_resource(db, jack, resource, "view", source_ip="10.20.9.101", session=None,
                                           record_count=20, is_synthetic=True, scenario="detection_test")
            assert not permitted
    data = risk(client, admin, "jack.silva")
    assert "restricted_denied" in rules_seen(data)
    assert data["current_stage"] == "sensitive_resource_access"
    assert data["exposure"]["sensitive_records_accessed"] == 0  # denied: nothing was accessed
    assert data["level"] != "critical" and alerts_for(client, admin, "jack.silva") == []


# ---------------------------------------------------------------- 4. large export
def test_large_export_is_collection_not_exfiltration(client, admin):
    with SessionLocal() as db:
        frank = employee(db, "frank.osei")
        _, permitted = access_resource(db, frank, "customer-accounts", "export", source_ip="10.20.5.61", session=None,
                                       record_count=25_000, is_synthetic=True, scenario="detection_test")
        assert permitted
    data = risk(client, admin, "frank.osei")
    assert "large_export" in rules_seen(data)
    assert data["current_stage"] == "collection" and "exfiltration" not in data["attack_stages"]
    exposure = data["exposure"]
    assert exposure["status"] == "confirmed_export" and exposure["records_exported"] == 25_000
    assert exposure["records_potentially_exposed"] == 25_000
    assert exposure["external_transfer_confirmed"] is False and exposure["exfiltration_established"] is False
    assert "exfiltration is not established" in exposure["statement"]
    assert data["confidence"] < get_settings().threat_high_threshold  # a single stage cannot be high risk
    assert alerts_for(client, admin, "frank.osei") == []


# ---------------------------------------------------------------- 5. failed logins
def test_multiple_failed_logins_are_credential_misuse(client, admin):
    with SessionLocal() as db:
        for _ in range(6):
            with pytest.raises(ServiceError):
                authenticate(db, "EMP-1007", "wrong-password", ip="10.20.6.71", synthetic=True, scenario="detection_test")
    data = risk(client, admin, "grace.lee")
    assert {"failed_login_burst"} <= rules_seen(data)
    assert data["current_stage"] == "credential_misuse"
    assert data["level"] != "critical" and alerts_for(client, admin, "grace.lee") == []
    with SessionLocal() as db:  # eventually the right password: compromise indicator
        authenticate(db, "EMP-1007", demo_password("EMP-1007"), ip="10.20.6.71", synthetic=True,
                     scenario="detection_test")
    assert "login_after_failures" in rules_seen(risk(client, admin, "grace.lee"))


# ---------------------------------------------------------------- 6. privileged account creation
def test_privileged_account_creation_is_persistence(client, admin):
    with SessionLocal() as db:
        david = employee(db, "david.kumar")
        authenticate(db, "EMP-1004", demo_password("EMP-1004"), ip=ATTACKER_IP, synthetic=True,
                     scenario="detection_test")
        steps = client.post("/api/simulation/steps", headers=admin, json={
            "target_employee_id": david.id, "step": "create_privileged_account", "source_ip": ATTACKER_IP})
    assert steps.json()["status"] == "completed"
    data = risk(client, admin, "david.kumar")
    assert "privileged_account_created" in rules_seen(data)
    assert {"privilege_escalation", "persistence"} <= set(data["attack_stages"])
    assert data["current_stage"] == "persistence"
    assert data["independent_stages"] == 2  # one event never counts as two independent stages


# ---------------------------------------------------------------- 7. external transfer
def test_external_transfer_exposure_distinguishes_attempt_from_confirmed(client, admin):
    with SessionLocal() as db:
        isla = employee(db, "isla.murphy")
        synthetic_event(db, isla, "external_transfer", ip="10.20.8.91", resource="loan-applications",
                        records_accessed=3000, records_downloaded=3000, details={"transfer_status": "attempted"})
    attempted = risk(client, admin, "isla.murphy")["exposure"]
    assert attempted["status"] != "confirmed_external_transfer" and attempted["exfiltration_established"] is False
    assert attempted["records_in_external_transfers"] == 3000 and "not confirmed" in attempted["statement"]

    with SessionLocal() as db:
        isla = employee(db, "isla.murphy")
        synthetic_event(db, isla, "external_transfer", ip="10.20.8.91", resource="loan-applications",
                        records_accessed=3000, records_downloaded=3000, details={"transfer_status": "confirmed"})
    data = risk(client, admin, "isla.murphy")
    assert data["exposure"]["status"] == "confirmed_external_transfer" and data["exposure"]["external_transfer_confirmed"]
    assert data["current_stage"] == "exfiltration"
    assert data["exposure"]["records_potentially_exposed"] == 3000  # attempt + confirmation are the same records


# ---------------------------------------------------------------- 8. complete attack
def test_complete_attack_alerts_critical_before_the_final_transfer(client, admin):
    with SessionLocal() as db:
        david_id = employee(db, "david.kumar").id
    confidence, alert_after = [], {}
    for step in STEPS:
        result = client.post("/api/simulation/steps", headers=admin, json={
            "target_employee_id": david_id, "step": step, "source_ip": ATTACKER_IP, "scenario": "it_admin_full_chain"}).json()
        assert result["status"] == "completed", result
        data = client.get(f"/api/risk/employees/{david_id}", headers=admin).json()
        confidence.append(data["confidence"])
        alert_after[step] = bool(alerts_for(client, admin, "david.kumar"))

    assert confidence == sorted(confidence)                       # related evidence only ever raises the score
    assert all(c <= 100 for c in confidence)                      # bounded
    assert confidence[0] < get_settings().threat_critical_threshold  # the first suspicious event is not critical
    assert alert_after["external_transfer"] and not alert_after["unfamiliar_login"]
    first_alert_step = next(s for s in STEPS if alert_after[s])
    assert STEPS.index(first_alert_step) < STEPS.index("external_transfer")   # early detection

    (alert,) = alerts_for(client, admin, "david.kumar")
    assert alert["severity"] == "critical" and alert["attack_confidence"] >= get_settings().threat_critical_threshold
    assert alert["id"] and alert["employee_id"] == david_id and alert["detected_at"] and alert["stage"] == "exfiltration"
    assert alert["first_event_id"] < alert["event_id"]
    assert alert["evidence"] and {"event_id", "rule", "stages", "relations"} <= set(alert["evidence"][0])
    assert {"collection", "persistence", "lateral_movement"} <= {s for ev in alert["evidence"] for s in ev["stages"]}
    assert alert["exposure"]["status"] in ("confirmed_export", "confirmed_external_transfer")
    actions = {(a["action"], a["target"]) for a in alert["recommended_actions"]}
    assert ("revoke_sessions", None) in actions and ("lock_account", "svc.backup01") in actions

    # The alert was raised by an earlier event, not by the external transfer itself.
    with SessionLocal() as db:
        transfer = db.scalar(select(SecurityEvent).where(SecurityEvent.event_type == "external_transfer",
                                                         SecurityEvent.is_synthetic.is_(True)))
        trigger = db.get(SecurityEvent, alert["event_id"])
        assert trigger.timestamp < transfer.timestamp and trigger.event_type != "external_transfer"
        assert datetime.fromisoformat(alert["detected_at"].replace("Z", "+00:00")) < transfer.timestamp


def test_attack_stages_follow_evidence_not_a_fixed_order(client, admin):
    """Export first, then probing, then unfamiliar login: the same stages are detected out of the usual order."""
    with SessionLocal() as db:
        grace = employee(db, "grace.lee")
        access_resource(db, grace, "audit-reports", "export", source_ip="10.20.6.71", session=None,
                        record_count=20_000, is_synthetic=True, scenario="detection_test")
        for resource in ("hr-records", "payroll-records", "it-admin-console"):
            access_resource(db, grace, resource, "view", source_ip=ATTACKER_IP, session=None, record_count=5,
                            is_synthetic=True, scenario="detection_test")
        authenticate(db, "EMP-1007", demo_password("EMP-1007"), ip=ATTACKER_IP, synthetic=True,
                     scenario="detection_test")
    data = risk(client, admin, "grace.lee")
    assert {"collection", "sensitive_resource_access", "initial_access"} <= set(data["attack_stages"])
    assert data["stage_history"][0] == "collection"          # first seen is not first in the usual chain
    assert data["independent_stages"] >= 3 and data["links"]["ips"] == [ATTACKER_IP]


# ---------------------------------------------------------------- 9. duplicates
def test_duplicate_requests_are_stored_and_scored_once(client, admin):
    bob = auth_header(client, "EMP-1002")
    body = {"event_type": "resource_access", "resource": "financial-reports", "record_count": 2, "request_id": "dup-test-1"}
    first = client.post("/api/events", headers=bob, json=body).json()
    second = client.post("/api/events", headers=bob, json=body).json()
    third = client.post("/api/events", headers={**bob, "Idempotency-Key": "dup-test-2"}, json={**body, "request_id": None}).json()
    again = client.post("/api/events", headers={**bob, "Idempotency-Key": "dup-test-2"}, json={**body, "request_id": None}).json()
    assert second["duplicate"] and second["event"]["id"] == first["event"]["id"]
    assert not third["duplicate"] and again["duplicate"] and again["event"]["id"] == third["event"]["id"]
    with SessionLocal() as db:
        count = len(db.scalars(select(SecurityEvent).where(SecurityEvent.request_id.in_(["dup-test-1", "dup-test-2"]))).all())
    assert count == 2


def test_repeated_identical_evidence_does_not_inflate_the_score(client, admin):
    def export(db, n):
        for _ in range(n):
            synthetic_event(db, employee(db, "emma.wilson"), "file_download", ip="10.20.4.51", resource="trading-reports",
                            records_accessed=9000, records_downloaded=9000)

    with SessionLocal() as db:
        export(db, 1)
    one = risk(client, admin, "emma.wilson")
    with SessionLocal() as db:
        export(db, 25)
    many = risk(client, admin, "emma.wilson")
    large = [f for f in many["factors"] if f["rule"] == "large_export"][0]
    assert large["count"] == 26 and large["points"] <= round(100 * 0.42 * 1.5)    # repeat discount and cap
    assert many["confidence"] - one["confidence"] < 12 and many["confidence"] <= 100
    assert many["independent_stages"] == one["independent_stages"] == 1
    assert many["confidence"] < get_settings().threat_high_threshold             # still one independent stage


# ---------------------------------------------------------------- 10. false positives
def test_false_positive_scenarios_stay_below_alert_level(client, admin):
    tz_hour = lambda h: local_today_at(h)
    scenarios = []
    with SessionLocal() as db:
        # after-hours login from the usual workstation
        alice = employee(db, "alice.morgan")
        scenarios.append(("after_hours", synthetic_event(db, alice, "login", ip="10.20.1.11", occurred_at=tz_hour(2)).threat))
        # travelling: unfamiliar IP, then ordinary permitted work
        isla = employee(db, "isla.murphy")
        synthetic_event(db, isla, "login", ip="203.0.113.77", occurred_at=tz_hour(10))
        for resource in ("loan-applications", "customer-accounts"):
            result, _ = access_resource(db, isla, resource, "view", source_ip="203.0.113.77", session=None, record_count=6,
                                        is_synthetic=True, scenario="detection_test")
        scenarios.append(("travelling", result.threat))
        # an IT administrator routinely creating an account from the usual workstation in business hours
        david = employee(db, "david.kumar")
        scenarios.append(("routine_admin", synthetic_event(
            db, david, "administrative_action", ip="10.20.3.41", resource="it-admin-console", occurred_at=tz_hour(11),
            details={"action": "create_privileged_account"}).threat))
        # a plausible 300-record download by someone who downloads regularly
        scenarios.append(("plausible_download", synthetic_event(
            db, alice, "file_download", ip="10.20.1.11", resource="financial-reports", records_accessed=300,
            records_downloaded=300, occurred_at=tz_hour(12)).threat))
        # two typing mistakes then the right password
        for _ in range(2):
            synthetic_event(db, employee(db, "frank.osei"), "login_failed", ip="10.20.5.61", outcome="failure",
                            occurred_at=tz_hour(9))
        scenarios.append(("typo_then_login", synthetic_event(db, employee(db, "frank.osei"), "login", ip="10.20.5.61",
                                                             occurred_at=tz_hour(9)).threat))
    for name, threat in scenarios:
        assert threat.confidence < get_settings().threat_high_threshold, (name, threat.confidence, threat.factors)
        assert threat.level in ("normal", "suspicious"), name
        assert threat.exposure["external_transfer_confirmed"] is False, name
    for username in ("alice.morgan", "isla.murphy", "david.kumar", "frank.osei"):
        assert alerts_for(client, admin, username) == [], username
