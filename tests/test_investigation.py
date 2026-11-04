"""Investigation and incident-response workflow: investigation record, evidence correlation and preservation,
explanation, attack classification, containment with enforcement, resolution and evidence export."""
import csv
import io
import json
import sqlite3
from datetime import datetime, timezone

import pytest
from conftest import auth_header, login

from backend import investigation_explainer
from backend.models import Employee, SecurityEvent

ATTACKER_IP = "185.220.101.45"
OTHER_IP = "203.0.113.50"
STEPS = ["unfamiliar_login", "restricted_access", "large_export", "admin_login_failures",
         "create_privileged_account", "privileged_login", "external_transfer"]


def pk_of(client, admin, username):
    return next(e["id"] for e in client.get("/api/employees", headers=admin).json() if e["username"] == username)


def attack(client, admin, username, steps, ip=ATTACKER_IP):
    pk = pk_of(client, admin, username)
    return [client.post("/api/simulation/steps", headers=admin, json={
        "target_employee_id": pk, "step": s, "source_ip": ip, "scenario": "it_admin_full_chain"}).json() for s in steps]


def investigation_for(client, admin, code):
    rows = [r for r in client.get("/api/soc/investigations", headers=admin).json() if r["employee_id"] == code]
    assert len(rows) == 1, rows
    return rows[0]["id"]


def detail(client, admin, inv_id):
    response = client.get(f"/api/investigations/{inv_id}", headers=admin)
    assert response.status_code == 200, response.text
    return response.json()


def contain(client, admin, body):
    return client.post("/api/containment", headers=admin, json=body)


def test_critical_alert_creates_an_investigation_with_a_complete_case_file(client, admin):
    attack(client, admin, "david.kumar", STEPS[:3])                      # stops before the external transfer
    alerts = client.get("/api/alerts", headers=admin).json()
    (alert,) = [a for a in alerts if a["employee_username"] == "david.kumar"]
    assert alert["risk_band"] == "critical" and alert["investigation_id"]
    inv = detail(client, admin, alert["investigation_id"])

    assert inv["employee_username"] == "david.kumar" and inv["status"] == "open" and inv["id"] == alert["investigation_id"]
    case = inv["case_file"]
    assert case["employee"]["employee_id"] == "EMP-1004"
    assert case["sessions"] and all(s["source_ip"] == ATTACKER_IP for s in case["sessions"])
    assert [ip["ip"] for ip in case["suspicious_ips"]] == [ATTACKER_IP]
    assert inv["first_event_id"] and inv["latest_event_id"] >= inv["first_event_id"]
    assert inv["first_event_id"] in case["event_ids"] and inv["latest_event_id"] in case["event_ids"]
    assert inv["risk_score"] >= 80 and inv["attack_stage"] in ("collection", "sensitive_resource_access")
    assert {s["resource"] for s in case["sensitive_resources"]} >= {"payroll-records"}
    data = case["data"]
    assert data["records_exported"] == 25_000 and data["records_potentially_exposed"] == 25_000
    assert data["confirmed_external_transfers"] == 0 and data["external_transfer_confirmed"] is False
    assert inv["exposure"]["status"] == "confirmed_export" and not inv["exposure"]["exfiltration_established"]

    # the investigation keeps updating as new related events arrive
    before = set(case["event_ids"])
    attack(client, admin, "david.kumar", STEPS[3:])
    later = detail(client, admin, inv["id"])
    assert later["id"] == inv["id"] and before < set(later["case_file"]["event_ids"])
    assert later["attack_stage"] == "exfiltration" and later["risk_score"] >= inv["risk_score"]
    assert later["case_file"]["data"]["confirmed_external_transfers"] == 1
    assert later["case_file"]["data"]["external_transfer_confirmed"] is True
    assert [a["username"] for a in later["case_file"]["related_accounts"]] == ["svc.backup01"]
    assert len([r for r in client.get("/api/soc/investigations", headers=admin).json() if r["employee_id"] == "EMP-1004"]) == 1


def test_evidence_is_correlated_by_session_ip_account_and_resource_and_stays_scoped(client, admin):
    alice = auth_header(client, "EMP-1001")                              # unrelated normal activity
    client.post("/api/resources/financial-reports/access", headers=alice, json={})
    attack(client, admin, "david.kumar", STEPS)
    inv = detail(client, admin, investigation_for(client, admin, "EMP-1004"))

    evidence = client.get(f"/api/investigations/{inv['id']}/evidence", headers=admin).json()
    by_id = {e["event_id"]: e for e in evidence["events"]}
    assert set(by_id) == set(inv["case_file"]["event_ids"]) and len(by_id) >= 12
    relations = {r for e in evidence["events"] for r in e["relations"]}
    assert {"flagged", "session", "ip", "related_account"} <= relations
    # nothing belonging to an unrelated employee is collected
    assert all(e["snapshot"]["employee_id"] != "EMP-1001" for e in evidence["events"])
    assert any(e["snapshot"]["account"] == "svc.backup01" for e in evidence["events"])
    assert {e["snapshot"]["source_ip"] for e in evidence["events"] if e["snapshot"]["account"] != "svc.backup01"} >= {ATTACKER_IP}

    # evidence is preserved: originals are unchanged by later activity, containment and resolution
    assert evidence["integrity"]["intact"] and evidence["integrity"]["verified"] == len(by_id)
    pk = pk_of(client, admin, "david.kumar")
    assert contain(client, admin, {"employee_id": pk, "action_type": "lock_account", "reason": "Containment", "confirm": True,
                                   "investigation_id": inv["id"]}).status_code == 201
    login(client, "EMP-1004")                                            # a refused login adds evidence, never edits it
    after = client.get(f"/api/investigations/{inv['id']}/evidence", headers=admin).json()
    assert after["integrity"]["intact"]
    now = {e["event_id"]: e for e in after["events"]}
    assert set(by_id) < set(now)                                          # the refused login was added as new evidence
    for event_id, original in by_id.items():
        assert now[event_id]["sha256"] == original["sha256"] and now[event_id]["snapshot"] == original["snapshot"]


def test_tampering_with_an_original_event_is_detected(client, admin, db_path):
    attack(client, admin, "david.kumar", STEPS[:3])
    inv = detail(client, admin, investigation_for(client, admin, "EMP-1004"))
    victim = inv["first_event_id"]
    with sqlite3.connect(db_path) as con:
        con.execute("UPDATE security_events SET records_downloaded = 1 WHERE id = ?", (victim,))
    check = client.get(f"/api/investigations/{inv['id']}/evidence", headers=admin).json()["integrity"]
    assert not check["intact"] and check["modified"] == [victim]
    report = client.get(f"/api/investigations/{inv['id']}/export", headers=admin).json()
    assert report["evidence_integrity"]["modified"] == [victim]
    assert next(e for e in report["correlated_events"] if e["event_id"] == victim)["integrity"] == "modified"


def _events_by_id(client, admin, employee_pks):
    found = {}
    for pk in employee_pks:
        page = client.get("/api/events", headers=admin, params={"employee_id": pk, "limit": 500}).json()["items"]
        found.update({e["id"]: e for e in page})
    return found


def test_explanation_is_built_only_from_real_events(client, admin):
    attack(client, admin, "david.kumar", STEPS[:3])
    inv_id = investigation_for(client, admin, "EMP-1004")
    early = client.get(f"/api/investigations/{inv_id}/explanation", headers=admin).json()["explanation"]
    assert early["engine"] == "deterministic-evidence-v1" and early["llm_used"] is False
    assert early["attack_type"]["type"] == "unauthorised_data_export" and early["attack_type"]["vector"] == "compromised_credentials"
    kinds = {c["type"]: c for c in early["classifications"]}
    assert set(kinds) == set(investigation_explainer.ATTACK_TYPES)
    assert kinds["confirmed_external_transfer"]["supported"] is False and kinds["unauthorised_data_export"]["supported"]
    assert kinds["compromised_credentials"]["supported"] and not kinds["possible_insider_misuse"]["supported"]

    attack(client, admin, "david.kumar", STEPS[3:])
    full = client.get(f"/api/investigations/{inv_id}/explanation", headers=admin).json()["explanation"]
    for section in ("attack_type", "current_stage", "suspicious_activities", "supporting_evidence", "risk_assessment", "potential_impact",
                    "recommended_containment", "missing_evidence", "alternative_explanations", "attribution"):
        assert full[section], section
    assert full["attack_type"]["type"] == "confirmed_external_transfer" and full["current_stage"]["key"] == "exfiltration"
    kinds = {c["type"]: c for c in full["classifications"]}
    assert all(kinds[k]["supported"] for k in ("confirmed_external_transfer", "privilege_escalation", "unauthorised_data_export",
                                                "compromised_credentials", "automated_account_exploitation"))
    assert "not who was operating it" in full["attribution"] and "identity" in full["attribution"]
    assert full["risk_assessment"]["risk_score"] >= 90 and full["synthetic"] is True
    assert "bank" in full["simulation_notice"]

    # every referenced event is a real stored event, with its real timestamp and address
    pks = [pk_of(client, admin, u) for u in ("david.kumar", "svc.backup01")]
    events = _events_by_id(client, admin, pks)
    refs = [r for sec in ("supporting_evidence",) for r in full[sec]]
    refs += [r for a in full["suspicious_activities"] for r in a["events"]]
    refs += [r for c in full["classifications"] for r in c["events"]]
    assert refs
    for ref in refs:
        stored = events[ref["event_id"]]
        assert datetime.fromisoformat(ref["timestamp"]) == datetime.fromisoformat(stored["timestamp"]).astimezone(timezone.utc)
    stored_ips = {e["source_ip"] for e in events.values()}
    known = set(client.get(f"/api/employees/{pks[0]}", headers=admin).json().get("known_ips", []))
    for item in full["supporting_evidence"]:
        assert item["source_ip"] == events[item["event_id"]]["source_ip"]
    text = json.dumps(full)
    mentioned = {w.strip(",.;()'\"") for w in text.replace("\\", " ").split() if w.strip(",.;()'\"").count(".") == 3
                 and w.strip(",.;()'\"").replace(".", "").isdigit()}
    assert mentioned <= stored_ips | known, mentioned - stored_ips - known
    assert not any("identity of the attacker is" in s.lower() for s in full["missing_evidence"])


def _fake(employee, event_id, event_type, ip, rules, *, resource=None, outcome="success", ts=0, records=0, stages=()):
    event = SecurityEvent(id=event_id, employee_id=employee.id, event_type=event_type, resource=resource, outcome=outcome, source_ip=ip,
                          records_accessed=records, records_downloaded=records, details={}, risk_points=40,
                          risk_flags=[{"rule": r, "severity": 0.4, "stages": list(stages)} for r in rules] if rules else [],
                          timestamp=datetime(2026, 1, 5, 10, 0, ts, tzinfo=timezone.utc))
    event.employee = employee
    return event


def test_classification_separates_insider_misuse_from_compromise_and_automation():
    me = Employee(id=1, employee_code="EMP-X", username="x", known_ips=["10.0.0.5"], department="Finance", job_role="Analyst")
    exposure = {"external_transfer_confirmed": False, "status": "confirmed_export", "records_exported": 5000}

    # a known address, a large export, no credential misuse: possible insider misuse, not compromise
    insider = [_fake(me, 1, "login", "10.0.0.5", [], ts=0),
               _fake(me, 2, "data_export", "10.0.0.5", ["large_export"], resource="financial-reports", records=5000, ts=30,
                     stages=["collection"])]
    kinds = {c["type"]: c["supported"] for c in investigation_explainer.classify(insider, me, exposure, {"10.0.0.5"})}
    assert kinds["possible_insider_misuse"] and kinds["unauthorised_data_export"]
    assert not kinds["compromised_credentials"] and not kinds["confirmed_external_transfer"]

    # unfamiliar address alone is not an attack classification
    lone = [_fake(me, 3, "login", "198.51.100.9", ["unfamiliar_ip"], stages=["initial_access"])]
    kinds = {c["type"]: c["supported"] for c in investigation_explainer.classify(lone, me, {"status": "none"}, {"10.0.0.5"})}
    assert not any(kinds.values())

    # a burst of failed logins at machine pace
    burst = [_fake(me, 10 + i, "login_failed", "198.51.100.9", ["failed_login_burst"], ts=i, stages=["credential_misuse"])
             for i in range(6)]
    kinds = {c["type"]: c["supported"] for c in investigation_explainer.classify(burst, me, {"status": "none"}, {"10.0.0.5"})}
    assert kinds["automated_account_exploitation"] and not kinds["possible_insider_misuse"]


def test_containment_requires_admin_confirmation_and_reason_and_changes_the_simulated_environment(client, admin):
    attack(client, admin, "david.kumar", STEPS)
    inv_id = investigation_for(client, admin, "EMP-1004")
    pk = pk_of(client, admin, "david.kumar")
    base = {"employee_id": pk, "investigation_id": inv_id, "reason": "Containment of simulated incident"}

    david, alice = auth_header(client, "EMP-1004"), auth_header(client, "EMP-1001")
    assert client.post("/api/containment", headers=alice, json={**base, "action_type": "lock_account", "confirm": True}).status_code == 403
    assert client.post("/api/containment", json={**base, "action_type": "lock_account", "confirm": True}).status_code == 401
    for action in ("revoke_sessions", "lock_account", "restrict_access", "remove_privileges", "block_ip", "resolve_investigation"):
        refused = contain(client, admin, {**base, "action_type": action, "target": ATTACKER_IP})
        assert refused.status_code == 400 and "Confirmation required" in refused.json()["detail"], action
    assert contain(client, admin, {**base, "action_type": "lock_account", "reason": "", "confirm": True}).status_code == 422

    # restrict one sensitive resource: only that permission goes
    assert client.post("/api/resources/source-code-repo/access", headers=david, json={}).status_code == 200
    restricted = contain(client, admin, {**base, "action_type": "restrict_access", "target": "source-code-repo", "confirm": True})
    assert restricted.status_code == 201 and restricted.json()["details"]["removed_permissions"] == [
        {"resource": "source-code-repo", "access_level": "read"}]
    assert client.post("/api/resources/source-code-repo/access", headers=david, json={}).status_code == 403

    # remove privileges: write access is downgraded, and the account created in the incident keeps nothing
    removed = contain(client, admin, {**base, "action_type": "remove_privileges", "confirm": True})
    assert removed.status_code == 201
    levels = {p["resource"]: p["access_level"] for p in client.get("/api/employees/me", headers=david).json()["permissions"]}
    assert levels["it-admin-console"] == "read"

    # block the source address: the attacker cannot start another session from it
    assert contain(client, admin, {**base, "action_type": "block_ip", "target": ATTACKER_IP, "confirm": True}).status_code == 201
    assert [r["status"] for r in attack(client, admin, "david.kumar", ["unfamiliar_login"])] == ["blocked"]

    # disable the account: no further logins, and active sessions are gone
    locked = contain(client, admin, {**base, "action_type": "lock_account", "confirm": True})
    assert locked.status_code == 201
    assert login(client, "EMP-1004").status_code == 403
    assert client.get("/api/employees/me", headers=david).status_code == 401

    # every action is attributed, timestamped, justified and audited
    actions = client.get("/api/containment", headers=admin, params={"investigation_id": inv_id}).json()
    assert {a["action_type"] for a in actions} == {"restrict_access", "remove_privileges", "block_ip", "lock_account"}
    admin_pk = pk_of(client, admin, "soc.admin")
    assert all(a["performed_by"] == admin_pk and a["reason"] and a["created_at"] and a["investigation_id"] == inv_id for a in actions)
    audit = client.get("/api/audit-logs", headers=admin, params={"limit": 200}).json()
    audit_actions = {a["action"] for a in (audit["items"] if isinstance(audit, dict) else audit)}
    assert {"containment_restrict_access", "containment_remove_privileges", "containment_block_ip",
            "containment_lock_account", "containment_failed"} <= audit_actions
    assert detail(client, admin, inv_id)["status"] == "contained"
    ips = client.get(f"/api/soc/investigations/{inv_id}", headers=admin).json()["case_file"]["suspicious_ips"]
    assert ips[0]["blocked"] is True


def test_resolving_an_investigation_is_a_confirmed_audited_action_and_keeps_the_evidence(client, admin):
    attack(client, admin, "david.kumar", STEPS[:4])
    inv_id = investigation_for(client, admin, "EMP-1004")
    count = len(detail(client, admin, inv_id)["case_file"]["event_ids"])

    no_confirm = client.post(f"/api/investigations/{inv_id}/resolve", headers=admin, json={"reason": "False alarm?"})
    assert no_confirm.status_code == 400 and detail(client, admin, inv_id)["status"] == "open"
    assert client.post(f"/api/investigations/{inv_id}/resolve", headers=auth_header(client, "EMP-1001"),
                       json={"reason": "x" * 5, "confirm": True}).status_code == 403
    resolved = client.post(f"/api/investigations/{inv_id}/resolve", headers=admin,
                           json={"reason": "Contained and verified with the employee", "confirm": True})
    assert resolved.status_code == 201 and resolved.json()["action_type"] == "resolve_investigation"
    done = detail(client, admin, inv_id)
    assert done["status"] == "resolved" and done["closed_at"]
    assert len(done["case_file"]["event_ids"]) == count and client.get(f"/api/investigations/{inv_id}/evidence",
                                                                      headers=admin).json()["integrity"]["intact"]
    assert [a for a in client.get("/api/alerts", headers=admin).json() if a["investigation_id"] == inv_id][0]["status"] == "resolved"
    assert client.post(f"/api/investigations/{inv_id}/resolve", headers=admin,
                       json={"reason": "again", "confirm": True}).status_code == 409
    audit = client.get("/api/audit-logs", headers=admin, params={"limit": 50}).json()
    assert any(a["action"] == "containment_resolve_investigation" for a in (audit["items"] if isinstance(audit, dict) else audit))
    assert client.patch(f"/api/investigations/{inv_id}", headers=admin, json={"status": "closed"}).status_code == 422


def test_export_contains_only_the_selected_investigation(client, admin):
    attack(client, admin, "david.kumar", STEPS)
    attack(client, admin, "emma.wilson", STEPS[:3], ip=OTHER_IP)                  # a second, unrelated investigation
    david_id, emma_id = investigation_for(client, admin, "EMP-1004"), investigation_for(client, admin, "EMP-1005")
    assert david_id != emma_id
    pk = pk_of(client, admin, "david.kumar")
    contain(client, admin, {"employee_id": pk, "action_type": "block_ip", "target": ATTACKER_IP, "reason": "Block", "confirm": True,
                            "investigation_id": david_id})

    assert client.get(f"/api/investigations/{david_id}/export", headers=auth_header(client, "EMP-1001")).status_code == 403
    assert client.get(f"/api/investigations/{david_id}/export").status_code == 401
    assert client.get("/api/investigations/99999/export", headers=admin).status_code == 404

    response = client.get(f"/api/investigations/{david_id}/export", headers=admin)
    assert response.status_code == 200 and response.headers["content-type"].startswith("application/json")
    assert f"investigation-{david_id}-EMP-1004.json" in response.headers["content-disposition"]
    report = response.json()
    assert set(report) == {"report", "incident_summary", "attack_timeline", "correlated_events", "risk_score_history",
                           "data_exposure_assessment", "containment_actions", "investigation_findings", "evidence_integrity"}
    summary = report["incident_summary"]
    assert summary["investigation_id"] == david_id and summary["employee_id"] == "EMP-1004"
    assert summary["heuristic_risk_score"] >= 90 and summary["current_stage"] == "exfiltration"
    assert summary["first_suspicious_event"]["event_id"] < summary["latest_suspicious_event"]["event_id"]
    assert report["report"]["generated_by"] == "SEC-9011" and report["report"]["synthetic"] is True

    ids = {e["event_id"] for e in report["correlated_events"]}
    emma_ids = {e["event_id"] for e in client.get(f"/api/investigations/{emma_id}/evidence", headers=admin).json()["events"]}
    assert ids and not ids & emma_ids
    assert all(e["employee_id"] in ("EMP-1004",) or e["account"] == "svc.backup01" for e in report["correlated_events"])
    assert all(OTHER_IP != e["source_ip"] for e in report["correlated_events"])
    assert {e["event_id"] for e in report["attack_timeline"]["events"]} == ids
    assert all(s["event_ids"] and set(s["event_ids"]) <= ids for s in report["attack_timeline"]["stages"] if s["reached"])
    history = report["risk_score_history"]
    assert history and all(h["event_id"] in ids for h in history) and [h["heuristic_risk_score"] for h in history] == sorted(h["heuristic_risk_score"] for h in history)
    exposure = report["data_exposure_assessment"]
    assert exposure["status"] == "confirmed_external_transfer" and exposure["records_confirmed_external"] == 25_000
    assert exposure["case_totals"]["confirmed_external_transfers"] == 1
    (block,) = [a for a in report["containment_actions"] if a["action"] == "block_ip"]
    assert block["performed_by"] == "SEC-9011" and block["target_employee_id"] == "EMP-1004" and block["reason"] == "Block"
    assert report["investigation_findings"]["attack_type"]["type"] == "confirmed_external_transfer"
    assert report["evidence_integrity"]["intact"] and report["evidence_integrity"]["checked"] == len(ids)
    assert "EMP-1005" not in json.dumps(report) and "emma" not in json.dumps(report).lower()

    csv_response = client.get(f"/api/investigations/{david_id}/export", headers=admin, params={"format": "csv"})
    assert csv_response.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(csv_response.text)))
    assert {int(r["event_id"]) for r in rows} == ids and {r["investigation_id"] for r in rows} == {str(david_id)}
    assert all(r["integrity"] == "verified" and len(r["sha256"]) == 64 for r in rows)
    assert client.get(f"/api/investigations/{david_id}/export", headers=admin, params={"format": "xml"}).status_code == 422
    audit = client.get("/api/soc/audit", headers=admin, params={"category": "investigations"}).json()["rows"]
    assert any(r["action"] == "investigation_exported" and r["actor"] == "SEC-9011" for r in audit)


def test_a_normal_employee_never_gets_an_investigation(client, admin):
    alice = auth_header(client, "EMP-1001")
    for resource in ("financial-reports", "my-payslips", "employee-directory"):
        client.post(f"/api/resources/{resource}/access", headers=alice, json={})
    assert [r for r in client.get("/api/soc/investigations", headers=admin).json() if r["employee_id"] == "EMP-1001"] == []
    assert client.get("/api/investigations/1/explanation", headers=alice).status_code == 403


def test_the_complete_workflow_end_to_end(client, admin):
    """Suspicious activity -> critical alert -> investigation -> evidence -> explanation -> containment -> enforcement -> export."""
    results = attack(client, admin, "david.kumar", STEPS[:4])
    assert all(r["status"] == "completed" for r in results)
    mine = [a for a in client.get("/api/alerts", headers=admin).json() if a["employee_username"] == "david.kumar"]
    assert len(mine) == 1, [(a["id"], a["status"], a["risk_band"], a["detected_at"], a["investigation_id"]) for a in mine]
    (alert,) = mine
    assert alert["risk_band"] == "critical"
    exposure = alert["exposure"]
    assert not exposure["external_transfer_confirmed"]                  # critical before the final external transfer
    inv = detail(client, admin, alert["investigation_id"])
    assert inv["case_file"]["event_ids"] and inv["explanation"]["attack_type"]["type"] == "unauthorised_data_export"

    pk = pk_of(client, admin, "david.kumar")
    assert contain(client, admin, {"employee_id": pk, "action_type": "lock_account", "reason": "Critical alert", "confirm": True,
                                   "investigation_id": inv["id"]}).status_code == 201
    assert login(client, "EMP-1004").status_code == 403                  # the containment changed the simulated environment

    report = client.get(f"/api/investigations/{inv['id']}/export", headers=admin).json()
    assert [a["action"] for a in report["containment_actions"]] == ["lock_account"]
    assert report["evidence_integrity"]["intact"] and report["incident_summary"]["status"] == "contained"
