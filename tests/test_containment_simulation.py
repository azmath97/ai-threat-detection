"""Containment is auditable and local: it records what was asked, by whom and with what result, changes only this
application's records, is idempotent on retry, is guarded against abuse, and never reaches an external service."""
import ast
import hashlib
import re
import smtplib
import socket
import sqlite3
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import auth_header, employee_id, run_scenario

from backend import response_service
from backend.response_service import ACTION_INFO, SCOPE_KEY, SCOPE_NOTICE

ROOT = Path(__file__).resolve().parent.parent
ALLOWED_TO_CHANGE = {"employees", "employee_sessions", "access_permissions", "containment_actions", "response_controls",
                     "security_alerts", "attack_investigations", "audit_logs"}


def _db(db_path, sql, args=()):
    with sqlite3.connect(db_path) as con:
        return con.execute(sql, args).fetchall()


def _mark(db_path, table):
    return _db(db_path, f"select coalesce(max(id), 0) from {table}")[0][0]


def _since(db_path, table, mark, where="1=1", args=()):
    """Rows added to `table` after `mark` (earlier tests leave audit and containment history behind)."""
    return _db(db_path, f"select count(*) from {table} where id > ? and {where}", (mark, *args))[0][0]


def _snapshot(db_path) -> dict[str, str]:
    """A digest of every table, so a test can name exactly which tables an action touched."""
    with sqlite3.connect(db_path) as con:
        tables = [r[0] for r in con.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%'")]
        return {t: hashlib.sha256(repr(con.execute(f"select * from {t} order by 1").fetchall()).encode()).hexdigest() for t in tables}


def _incident(client, admin):
    """A simulated incident with an alert and an investigation, created by the detector (not by the test)."""
    for seed in range(1, 12):
        run = run_scenario(client, admin, "compromised_account_campaign", seed=seed)
        if run["observed"]["alert_ids"]:
            return run, run["observed"]["alert_ids"][0], run["observed"]["investigation_ids"][0]
        client.post("/api/simulation/reset", headers=admin)
    pytest.fail("no seed produced an alert")


def _contain(client, admin, **body):
    return client.post("/api/containment", headers=admin, json={"reason": "Simulated drill", "confirm": True, **body})


# ------------------------------------------------------------------------------------------------- the record
def test_a_simulated_action_records_the_alert_investigation_initiator_time_and_result(client, admin, db_path):
    run, alert_id, inv_id = _incident(client, admin)
    target = run["target"]["id"]
    response = _contain(client, admin, employee_id=target, action_type="lock_account", investigation_id=inv_id, alert_id=alert_id)
    assert response.status_code == 201, response.text
    action = response.json()
    assert action["simulated"] is True and action["scope"] == SCOPE_KEY and action["status"] == "completed"
    assert action["status_label"] == "Containment completed" and action["result"].startswith("Containment completed: ")
    assert action["alert_id"] == alert_id and action["investigation_id"] == inv_id and action["employee_id"] == target
    assert action["performed_by_username"] == "soc.admin" and action["reason"] == "Simulated drill"
    assert action["external_systems_contacted"] == [] and action["replayed"] is False
    assert any("this application's database" in e for e in action["effects"])
    assert any(e.startswith("Account record") and "locked" in e for e in action["effects"])
    assert action["created_at"]

    listed = client.get("/api/containment", headers=admin, params={"investigation_id": inv_id}).json()
    assert [a["id"] for a in listed] == [action["id"]] and listed[0]["result"] == action["result"]
    audit = [r for r in client.get("/api/audit-logs", headers=admin, params={"limit": 100}).json() if r["action"] == "containment_lock_account"]
    assert audit and audit[0]["details"]["scope"] == SCOPE_KEY and audit[0]["details"]["alert_id"] == alert_id
    assert audit[0]["details"]["investigation_id"] == inv_id and audit[0]["details"]["result"] == action["result"]
    assert audit[0]["actor_id"] == action["performed_by"]
    assert _db(db_path, "select alert_id, investigation_id, performed_by from containment_actions where id=?", (action["id"],)) == \
        [(alert_id, inv_id, action["performed_by"])]


def test_an_alert_alone_links_its_investigation_and_a_wrong_alert_is_refused(client, admin):
    run, alert_id, inv_id = _incident(client, admin)
    target = run["target"]["id"]
    other = employee_id(client, admin, "jack.silva" if run["target"]["username"] != "jack.silva" else "isla.murphy")
    assert _contain(client, admin, employee_id=other, action_type="restrict_access", alert_id=alert_id).status_code == 400
    assert _contain(client, admin, employee_id=target, action_type="lock_account", alert_id=99999).status_code == 404
    done = _contain(client, admin, employee_id=target, action_type="restrict_access", alert_id=alert_id)
    assert done.status_code == 201 and done.json()["investigation_id"] == inv_id and done.json()["alert_id"] == alert_id
    # an investigation alone records the alert it belongs to
    by_investigation = _contain(client, admin, employee_id=target, action_type="remove_privileges", investigation_id=inv_id)
    assert by_investigation.status_code in (201, 409)
    if by_investigation.status_code == 201:
        assert by_investigation.json()["alert_id"] == alert_id


def test_the_response_centre_and_export_state_the_scope_and_carry_the_result(client, admin):
    run, alert_id, inv_id = _incident(client, admin)
    done = _contain(client, admin, employee_id=run["target"]["id"], action_type="lock_account", investigation_id=inv_id).json()
    centre = client.get("/api/soc/response", headers=admin).json()
    assert centre["scope_notice"] == SCOPE_NOTICE and "does not contact or change any firewall" in SCOPE_NOTICE
    entry = next(h for h in centre["history"] if h["id"] == done["id"])
    assert entry["simulated"] is True and entry["result"] == done["result"] and entry["alert_id"] == alert_id
    assert "simulated" not in entry["label"].lower()
    report = client.get(f"/api/investigations/{inv_id}/export", headers=admin, params={"format": "json"}).json()
    exported = next(a for a in report["containment_actions"] if a["action_id"] == done["id"])
    assert exported["simulated"] is True and exported["scope"] == SCOPE_KEY and exported["result"] == done["result"]
    assert "changed only this application's own records" in report["report"]["notice"]
    detail = client.get(f"/api/soc/investigations/{inv_id}", headers=admin).json()
    assert detail["containment_actions"][0]["simulated"] is True and detail["containment_actions"][0]["result"] == done["result"]


# ------------------------------------------------------------------------------------------------- idempotency
def test_retrying_with_the_same_key_replays_the_original_action(client, admin, db_path):
    run, _, inv_id = _incident(client, admin)
    audit_mark, action_mark = _mark(db_path, "audit_logs"), _mark(db_path, "containment_actions")
    body = dict(employee_id=run["target"]["id"], action_type="revoke_sessions", investigation_id=inv_id,
                idempotency_key="retry-key-0001")
    first = _contain(client, admin, **body)
    second = _contain(client, admin, **body)
    third = _contain(client, admin, **body)
    assert first.status_code == 201 and second.status_code == third.status_code == 200
    assert first.json()["replayed"] is False and second.json()["replayed"] is True
    assert first.json()["id"] == second.json()["id"] == third.json()["id"] and second.json()["result"] == first.json()["result"]
    assert _since(db_path, "containment_actions", action_mark) == 1
    assert _since(db_path, "audit_logs", audit_mark, "action='containment_revoke_sessions'") == 1
    assert _since(db_path, "audit_logs", audit_mark, "action='containment_replayed'") == 2


def test_reusing_a_key_for_a_different_request_is_refused(client, admin, db_path):
    run, _, _ = _incident(client, admin)
    target = run["target"]["id"]
    mark = _mark(db_path, "containment_actions")
    assert _contain(client, admin, employee_id=target, action_type="revoke_sessions", idempotency_key="shared-key-0001").status_code == 201
    clash = _contain(client, admin, employee_id=target, action_type="lock_account", idempotency_key="shared-key-0001")
    assert clash.status_code == 409 and "different containment request" in clash.json()["detail"]
    assert _since(db_path, "containment_actions", mark, "action_type='lock_account'") == 0
    assert _db(db_path, "select status from employees where id=?", (target,)) == [("active",)]


def test_requests_that_would_change_nothing_do_not_create_duplicate_actions(client, admin, db_path):
    run, _, _ = _incident(client, admin)
    target = run["target"]["id"]
    assert _contain(client, admin, employee_id=target, action_type="lock_account").status_code == 201
    count = _db(db_path, "select count(*) from containment_actions")[0][0]
    audit_mark = _mark(db_path, "audit_logs")
    for _ in range(3):
        assert _contain(client, admin, employee_id=target, action_type="lock_account").status_code == 409
        assert _contain(client, admin, employee_id=target, action_type="revoke_sessions").status_code == 409      # nothing active left
    assert _db(db_path, "select count(*) from containment_actions")[0][0] == count
    assert _since(db_path, "audit_logs", audit_mark, "action='containment_failed'") == 6                        # refusals are audited
    ip = _contain(client, admin, employee_id=target, action_type="block_ip", target="203.0.113.77")
    assert ip.status_code == 201
    assert _contain(client, admin, employee_id=target, action_type="block_ip", target="203.0.113.77").status_code == 409
    assert _contain(client, admin, employee_id=target, action_type="unblock_ip", target="203.0.113.77").status_code == 201   # tidy up


def test_resolving_an_investigation_is_idempotent_with_a_key(client, admin, db_path):
    _, _, inv_id = _incident(client, admin)
    mark = _mark(db_path, "containment_actions")
    body = {"reason": "Drill complete", "confirm": True, "idempotency_key": "resolve-key-0001"}
    first = client.post(f"/api/investigations/{inv_id}/resolve", headers=admin, json=body)
    again = client.post(f"/api/investigations/{inv_id}/resolve", headers=admin, json=body)
    assert first.status_code == 201 and again.status_code == 200 and again.json()["replayed"] is True
    assert first.json()["id"] == again.json()["id"] and first.json()["result"].startswith("Containment completed")
    assert _since(db_path, "containment_actions", mark, "action_type='resolve_investigation'") == 1
    assert client.post(f"/api/investigations/{inv_id}/resolve", headers=admin, json={"reason": "Again", "confirm": True}).status_code == 409


@pytest.mark.parametrize("key", ["short", "has spaces in it", "x" * 65, "bad/char/key!"])
def test_malformed_idempotency_keys_are_rejected(client, admin, key):
    assert _contain(client, admin, employee_id=1, action_type="lock_account", idempotency_key=key).status_code == 422


# ----------------------------------------------------------------------------------------- unauthorised and repeated
def test_unauthorised_containment_requests_are_refused_and_audited(client, admin, db_path):
    alice = auth_header(client, "EMP-1001")
    bob = employee_id(client, admin, "bob.chen")
    alice_login_audit = _mark(db_path, "audit_logs")
    before = _snapshot(db_path)
    for call in (lambda h: client.post("/api/containment", headers=h, json={"employee_id": bob, "action_type": "lock_account",
                                                                          "reason": "malicious", "confirm": True}),
                 lambda h: client.post("/api/investigations/1/resolve", headers=h, json={"reason": "nope", "confirm": True})):
        assert call(alice).status_code == 403
        assert call({}).status_code == 401
    after = _snapshot(db_path)
    changed = {t for t in after if after[t] != before[t]}
    assert changed == {"audit_logs", "access_denials"}                            # only the refusals themselves were recorded
    assert _db(db_path, "select count(*) from access_denials") == [(4,)]          # 2 forbidden + 2 unauthenticated, nothing else
    rows = _db(db_path, "select actor_id, details from audit_logs where action='containment_unauthorized' and id > ?", (alice_login_audit,))
    assert len(rows) == 2 and all(r[0] is not None for r in rows)
    assert _db(db_path, "select status from employees where id=?", (bob,)) == [("active",)]


def test_an_administrator_cannot_contain_their_own_account_and_confirmation_is_enforced(client, admin):
    soc = employee_id(client, admin, "soc.admin")
    assert _contain(client, admin, employee_id=soc, action_type="lock_account").status_code == 400
    bob = employee_id(client, admin, "bob.chen")
    assert client.post("/api/containment", headers=admin, json={"employee_id": bob, "action_type": "lock_account",
                                                                "reason": "no confirmation"}).status_code == 400


def test_repeated_containment_requests_are_rate_limited(client, admin, db_path, monkeypatch):
    monkeypatch.setattr("backend.rate_limit.get_settings", lambda: SimpleNamespace(containment_max_per_minute=3))
    bob = employee_id(client, admin, "bob.chen")
    audit_mark, action_mark = _mark(db_path, "audit_logs"), _mark(db_path, "containment_actions")
    codes = [_contain(client, admin, employee_id=bob, action_type="restore_account").status_code for _ in range(5)]
    assert codes[:3] == [409, 409, 409] and codes[3:] == [429, 429]
    limited = _contain(client, admin, employee_id=bob, action_type="restore_account")
    assert limited.status_code == 429 and int(limited.headers["Retry-After"]) >= 1
    assert _since(db_path, "audit_logs", audit_mark, "action='containment_rate_limited'") == 3
    assert _since(db_path, "containment_actions", action_mark) == 0
    assert client.get("/api/containment", headers=admin).status_code == 200      # reading history is not limited


# ----------------------------------------------------------------------- only simulated state changes, nothing external
ALL_ACTIONS = [("remove_privileges", None), ("revoke_sessions", None), ("restrict_access", None), ("block_ip", "203.0.113.88"),
               ("isolate_system", "customer-accounts"), ("lock_account", None), ("restore_account", None),
               ("unblock_ip", "203.0.113.88"), ("release_system", "customer-accounts")]


def test_every_action_changes_only_this_applications_records_and_contacts_nothing_external(client, admin, db_path, monkeypatch):
    run, _, inv_id = _incident(client, admin)
    target = run["target"]["id"]

    def forbidden(*args, **kwargs):
        raise AssertionError("containment attempted an external operation")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(smtplib.SMTP, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    import http.client
    import urllib.request

    monkeypatch.setattr(http.client.HTTPConnection, "connect", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    try:
        import requests

        monkeypatch.setattr(requests.Session, "request", forbidden)
    except ImportError:
        pass

    evidence_before = _snapshot(db_path)
    performed = []
    for action, value in ALL_ACTIONS:
        before = _snapshot(db_path)
        body = dict(employee_id=target, action_type=action, investigation_id=inv_id)
        if value:
            body["target"] = value
        response = _contain(client, admin, **body)
        if action == "remove_privileges" and response.status_code == 409:       # the employee may hold no write access
            assert "No elevated privileges" in response.json()["detail"]
            continue
        assert response.status_code == 201, (action, response.text)
        out = response.json()
        performed.append(action)
        assert out["scope"] == SCOPE_KEY and out["external_systems_contacted"] == [] and out["simulated"] is True
        after = _snapshot(db_path)
        changed = {t for t in after if after[t] != before[t]}
        assert changed <= ALLOWED_TO_CHANGE, (action, changed - ALLOWED_TO_CHANGE)
        assert {"containment_actions", "audit_logs"} <= changed                  # recorded and audited, every time
    assert set(performed) >= {a for a, _ in ALL_ACTIONS} - {"remove_privileges"}
    final = _snapshot(db_path)
    for evidence_table in ("security_events", "investigation_evidence", "risk_assessments"):
        assert final[evidence_table] == evidence_before[evidence_table], evidence_table      # evidence is never altered
    effects = " ".join(e for a in client.get("/api/containment", headers=admin).json() for e in a["effects"])
    assert "no firewall or network device is changed" in effects


def test_containment_takes_effect_only_through_this_backends_own_checks(client, admin):
    run, _, _ = _incident(client, admin)
    target, code = run["target"]["id"], run["target"]["employee_id"]
    from conftest import login

    assert _contain(client, admin, employee_id=target, action_type="lock_account").status_code == 201
    refused = login(client, code)
    assert refused.status_code == 403 and "locked" in refused.json()["detail"].lower()
    assert _contain(client, admin, employee_id=target, action_type="restore_account").status_code == 201
    assert login(client, code).status_code == 200


def test_the_backend_has_no_code_path_to_external_systems():
    forbidden = {"socket", "smtplib", "requests", "httpx", "urllib.request", "http.client", "subprocess", "ftplib", "telnetlib",
                 "paramiko", "boto3", "ldap3", "pexpect", "aiohttp", "winrm", "pywinrm", "scapy"}
    offenders = []
    for path in sorted((ROOT / "backend").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
            offenders += [(path.name, n) for n in names if n in forbidden or n.split(".")[0] in forbidden]
    allowed = {("security.py", "socket")}          # none expected; listed so an addition must be a conscious decision
    assert set(offenders) <= allowed, offenders
    source = (ROOT / "backend" / "response_service.py").read_text(encoding="utf-8")
    assert "os.system" not in source and "Popen" not in source


# ------------------------------------------------------------------------------------------------ claims and wording
def test_labels_and_notices_state_the_real_scope():
    assert not any("simulat" in label.lower() for _, (label, _, _) in ACTION_INFO.items())
    for needle in ("inside this application", "own records", "does not contact or change any firewall"):
        assert needle.lower() in SCOPE_NOTICE.lower()
    assert response_service.RESULT_PREFIX == "Containment completed: "


FORBIDDEN_CLAIMS = [r"threat blocked", r"attack blocked", r"attack stopped", r"quarantin", r"protects? (the |a )?(real )?bank",
                    r"blocks? real (network|traffic)", r"disables? real accounts?", r"live enforcement", r"stops? (a )?real attackers?"]


def test_no_user_facing_text_claims_real_enforcement():
    files = [*sorted((ROOT / "frontend").glob("*.py")), *sorted((ROOT / "backend").glob("*.py")), ROOT / "README.md",
             *sorted((ROOT / "docs").glob("*.md"))]
    hits = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_CLAIMS:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                line = text[max(0, text.rfind("\n", 0, match.start()) + 1):text.find("\n", match.end())]
                if not re.search(r"\b(not|no|never|nor|without|cannot|avoid|does not|doesn't)\b", line, flags=re.IGNORECASE):
                    hits.append((path.name, line.strip()[:120]))
    assert not hits, hits


def test_the_readme_states_what_is_enforced_and_what_is_not():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for statement in ("does not block real network traffic", "does not disable real accounts", "does not quarantine real devices",
                      "does not protect a real bank"):
        assert statement in text, statement
    for scripted in ("Demo script", "Run containment", "Containment completed"):
        assert scripted in text
