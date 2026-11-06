"""Deployment hardening, ML volume guard, dataset evaluation, randomised simulation and containment scope."""
import csv
import random
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from backend import security
from backend.config import get_settings, validate_for_environment
from backend.rate_limit import login_throttle
from backend.response_service import SCOPE_NOTICE
from conftest import login
from ml import synthetic_data as sd
from ml.anomaly_detector import get_detector, volume_guard
from ml.evaluate_dataset import evaluate
from ml.features import FEATURE_NAMES

KEY = "k" * 32


def _last_session_ip(db_path, employee_code):
    with sqlite3.connect(db_path) as con:
        return con.execute(
            "select s.ip_address from employee_sessions s join employees e on e.id = s.employee_id "
            "where e.employee_code = ? order by s.id desc limit 1", (employee_code,)).fetchone()[0]


# ------------------------------------------------------------------ trusted frontend / production settings
def test_trusted_frontend_key_attributes_workstation_ip_only_with_the_key(client, db_path, monkeypatch):
    settings = replace(get_settings(), map_loopback_to_workstation=False, trusted_frontend_key=KEY)
    monkeypatch.setattr(security, "get_settings", lambda: settings)

    assert login(client, "EMP-1001", headers={"X-Frontend-Key": "wrong" * 8}).status_code == 200
    assert _last_session_ip(db_path, "EMP-1001") == "0.0.0.0"             # unproven caller: the peer address is recorded

    assert login(client, "EMP-1001", headers={"X-Frontend-Key": KEY, "X-Forwarded-For": "203.0.113.9"}).status_code == 200
    assert _last_session_ip(db_path, "EMP-1001") == "10.20.1.11"          # registered workstation; X-Forwarded-For ignored


def test_trusted_frontend_is_disabled_without_a_configured_key(client, db_path, monkeypatch):
    settings = replace(get_settings(), map_loopback_to_workstation=False, trusted_frontend_key="")
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    assert login(client, "EMP-1002", headers={"X-Frontend-Key": ""}).status_code == 200
    assert _last_session_ip(db_path, "EMP-1002") == "0.0.0.0"


def test_production_refuses_sqlite_unless_explicitly_allowed():
    base = replace(get_settings(), secret_key="s" * 40, trusted_frontend_key=KEY, auto_seed=False, app_env="production", lab_mode=False)
    sqlite_settings = replace(base, database_url="sqlite:///./x.db", allow_sqlite_in_production=False)
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        validate_for_environment(sqlite_settings)
    validate_for_environment(replace(sqlite_settings, allow_sqlite_in_production=True))
    validate_for_environment(replace(base, database_url="postgresql+psycopg://u:p@db.example.test/w"))


def test_production_refuses_missing_default_or_short_secrets():
    base = replace(get_settings(), database_url="postgresql+psycopg://u:p@db.example.test/w", lab_mode=False)
    validate_for_environment(replace(base, app_env="development"))
    for bad in ("", "dev-only-secret-" + "change-me", "change-me-for-anything-other-than-a-local-demo", "short", "secret" + "x" * 40):
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            validate_for_environment(replace(base, app_env="production", secret_key=bad))
    with pytest.raises(RuntimeError):
        validate_for_environment(replace(base, app_env="production", secret_key="s" * 40, trusted_frontend_key="tiny"))
    validate_for_environment(replace(base, app_env="production", secret_key="s" * 40, trusted_frontend_key=KEY))


# ------------------------------------------------------------------ login throttle
def test_repeated_failed_logins_are_throttled_and_audited(client, db_path):
    login_throttle.reset()
    for _ in range(get_settings().login_max_failures):
        assert login(client, "EMP-1010", "Wrong-Password#1").status_code == 401
    blocked = login(client, "EMP-1010")                                   # even the right password is refused during lockout
    assert blocked.status_code == 429 and int(blocked.headers["Retry-After"]) > 0
    assert login(client, "EMP-1009").status_code == 200                   # other accounts are unaffected
    with sqlite3.connect(db_path) as con:
        assert con.execute("select count(*) from audit_logs where action = 'login_throttled'").fetchone()[0] >= 1
    login_throttle.reset()
    assert login(client, "EMP-1010").status_code == 200


def test_successful_login_clears_the_failure_count(client):
    login_throttle.reset()
    for _ in range(get_settings().login_max_failures - 1):
        assert login(client, "EMP-1008", "Wrong-Password#1").status_code == 401
    assert login(client, "EMP-1008").status_code == 200
    assert login(client, "EMP-1008", "Wrong-Password#1").status_code == 401   # counter restarted, so no lockout yet
    login_throttle.reset()


# ------------------------------------------------------------------ ML volume guard
def _features(**over):
    base = dict.fromkeys(FEATURE_NAMES, 0.0)
    base["login_hour"] = 10.0
    return {**base, **over}


def test_volume_guard_scores_bulk_volumes_the_forest_cannot_extrapolate_to(client):
    from math import log1p

    detector = get_detector()
    assert detector.available and detector.status()["volume_reference"]
    plausible = detector.score(_features(download_volume=log1p(300)))
    bulk = detector.score(_features(download_volume=log1p(30_000)))
    assert plausible.volume_guard == 0.0 and plausible.score < 0.5
    assert bulk.volume_guard >= 0.5 and bulk.score >= 0.5 and bulk.mode == "isolation_forest"
    assert volume_guard(_features(download_volume=log1p(30_000)), None) == 0.0   # models without a reference are unchanged


def test_training_reports_forest_only_and_combined_bulk_recall(client):
    metrics = get_detector().status()["metrics"]
    assert metrics["attack_recall_by_scenario"]["bulk_export"] >= 0.9
    assert metrics["bulk_export_recall_isolation_forest_only"] < 0.5          # the weakness the guard compensates for


# ------------------------------------------------------------------ dataset evaluation
def _write_event_csv(path, seed=11, employees=10):
    rng, ids = random.Random(seed), sd._Ids()
    start = datetime(2025, 3, 3, tzinfo=timezone.utc)
    rows = []
    for i in range(employees):
        emp = sd._make_employee(rng, i)
        for d in range(0, 28):
            day = start + timedelta(days=d)
            if day.weekday() < 5:
                rows += [(emp, e, 0, "normal") for e in sd.normal_session(rng, emp, day, ids)]
        for d in range(28, 44):
            day = start + timedelta(days=d)
            if day.weekday() < 5:
                rows += [(emp, e, 0, "normal") for e in sd.normal_session(rng, emp, day, ids)]
        for k, kind in enumerate(("bulk_export", "full_chain", "brute_force")):
            day = start + timedelta(days=45 + k)
            rows += [(emp, e, 1, kind) for e in sd.attack_window(rng, emp, kind, day, ids)]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["employee_id", "timestamp", "event_type", "source_ip", "resource", "outcome", "records_accessed",
                    "records_downloaded", "session_id", "department", "label", "scenario"])
        for emp, e, label, scenario in rows:
            w.writerow([emp.id, e.timestamp.isoformat(), e.event_type, e.source_ip, e.resource or "", e.outcome,
                        e.records_accessed, e.records_downloaded, e.session_id or "", emp.department, label, scenario])


def test_evaluate_dataset_scores_an_external_event_csv(client, tmp_path):
    events = tmp_path / "events.csv"
    _write_event_csv(events)
    report = evaluate(events, model_path=get_detector().path)
    assert report["model_mode"] == "isolation_forest" and report["n_employees"] == 10
    assert report["n_malicious_windows"] >= 30 and report["n_normal_windows"] > 50
    assert report["roc_auc"] > 0.9 and report["recall"] > 0.8 and report["false_positive_rate"] < 0.2
    assert set(report["recall_by_scenario"]) == {"bulk_export", "full_chain", "brute_force"}


def test_evaluate_dataset_without_labels_reports_distribution_only(client, tmp_path):
    events, plain = tmp_path / "events.csv", tmp_path / "plain.csv"
    _write_event_csv(events)
    with open(events, newline="", encoding="utf-8") as src, open(plain, "w", newline="", encoding="utf-8") as dst:
        reader = csv.DictReader(src)
        keep = [c for c in reader.fieldnames if c not in ("label", "scenario")]
        out = csv.DictWriter(dst, fieldnames=keep)
        out.writeheader()
        out.writerows({k: row[k] for k in keep} for row in reader)
    report = evaluate(plain, model_path=get_detector().path)
    assert "roc_auc" not in report and "note" in report and report["n_windows"] > 0


def test_evaluate_dataset_rejects_a_file_missing_required_columns(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("who,when\nx,2025-01-01\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required column"):
        evaluate(bad)


# ------------------------------------------------------------------ containment scope
def test_containment_states_its_real_scope(client, admin):
    centre = client.get("/api/soc/response", headers=admin).json()
    assert centre["scope_notice"] == SCOPE_NOTICE and "does not contact or change any firewall" in SCOPE_NOTICE
    employees = client.get("/api/employees", headers=admin).json()
    target = next(e["id"] for e in employees if e["username"] == "jack.silva")
    done = client.post("/api/containment", headers=admin, json={
        "employee_id": target, "action_type": "revoke_sessions", "reason": "scope label check", "confirm": True})
    assert done.status_code in (200, 201) and done.json()["details"]["scope"] == "simulated_application_state"
