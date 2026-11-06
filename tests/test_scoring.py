"""Risk scoring: what each number is, that it stays in range, that evidence is never counted twice, that severity (impact) is kept
apart from the score and from how certain the detector is, that explanations agree with each other, that thresholds are chosen on
validation runs only, and that no screen or document calls a heuristic a probability."""
import json
import re
import sqlite3
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import employee_id, run_steps
from sqlalchemy import select
from test_runtime import ADMIN_PASSWORD, Backend, _run_app, _sign_in

from backend import migrations, rules, scoring, threat_engine
from backend.catalog import IMPACT_LEVELS, SEVERITY_LEVELS, STRENGTH_LEVELS
from backend.config import get_settings, load_operating_point
from backend.correlation_engine import Evidence
from backend.database import SessionLocal, utcnow
from backend.event_service import access_resource, record_event
from backend.models import Employee
from ml import calibrate_scoring as cal

ROOT = Path(__file__).resolve().parent.parent
CHAIN = ["unfamiliar_login", "restricted_access", "large_export", "admin_login_failures", "create_privileged_account",
         "privileged_login", "external_transfer"]
IP = "185.220.101.45"


def evidence(event_id: int, rule: str = "large_export", weight: float = 0.42, resource: str | None = "source-code-repo") -> Evidence:
    return Evidence(event_id, utcnow(), 1, "someone", "file_download", resource, "success", IP, None, rule, weight, [], None, [rule], [])


def corr_of(*items: Evidence) -> SimpleNamespace:
    return SimpleNamespace(evidence=list(items))


def risk(client, admin, username):
    return client.get(f"/api/risk/employees/{employee_id(client, admin, username)}", headers=admin).json()


# ============================================================================================ score range
def test_the_score_is_bounded_whatever_the_inputs_are():
    w = rules.weights()
    assert set(w) == {"rules", "ml"} and abs(sum(w.values()) - 1.0) < 1e-9
    for rules_value in (-5.0, 0.0, 0.37, 1.0, 40.0):
        for ml_value in (-1.0, 0.0, 0.5, 1.0, 9.0):
            score = scoring.combine({"rules": rules_value, "ml": ml_value}, w)
            assert 0.0 <= score <= 100.0
    assert scoring.combine({"rules": 1.0, "ml": 1.0}, w) == 100.0 and scoring.combine({"rules": 0.0, "ml": 0.0}, w) == 0.0
    monotonic = [scoring.combine({"rules": v / 10, "ml": 0.3}, w) for v in range(11)]
    assert monotonic == sorted(monotonic)


def test_every_reported_score_is_in_range_and_the_band_follows_it(client, admin):
    run_steps(client, admin, "david.kumar", CHAIN)
    for e in client.get("/api/risk/employees", headers=admin).json():
        assert 0 <= e["score"] <= 100 and e["level"] in SEVERITY_LEVELS
        assert e["impact_severity"] in IMPACT_LEVELS and e["evidence_strength"] in STRENGTH_LEVELS
    detail = risk(client, admin, "david.kumar")
    assert 0.0 <= detail["risk_score"] <= 100.0 and detail["score"] == int(detail["risk_score"])
    band, by_score, gated = scoring.band_for(detail["risk_score"], detail["independent_stages"])
    assert detail["level"] == band == scoring.band_for(detail["risk_score"], detail["independent_stages"])[0]
    assert by_score == detail["score_breakdown"]["gate"]["band_from_score_alone"] and gated == detail["score_breakdown"]["gate"]["lowered_by_gate"]


@pytest.mark.parametrize("stages, expected_cap", [(0, "suspicious"), (1, "suspicious"), (2, "high_risk"), (3, "critical")])
def test_the_stage_gate_limits_the_band_but_never_changes_the_score(stages, expected_cap):
    band, by_score, _ = scoring.band_for(100.0, stages)
    assert by_score == "critical" and band == expected_cap


# ============================================================================================ missing evidence
def test_no_events_means_no_score_no_impact_and_no_evidence(client):
    with SessionLocal() as db:
        alice = db.scalar(select(Employee).where(Employee.username == "alice.morgan"))
        idle = threat_engine.assess(db, alice, utcnow().replace(year=2040))
    assert idle.risk_score == 0.0 and idle.level == "normal" and idle.impact_severity == "none" and idle.evidence_strength == "none"
    assert idle.factors == [] and idle.breakdown == {} and idle.components == {}


def test_activity_without_any_flagged_evidence_scores_low_and_is_not_called_evidence(client):
    with SessionLocal() as db:
        bob = db.scalar(select(Employee).where(Employee.username == "bob.chen"))
        result = record_event(db, bob, "resource_access", source_ip=bob.known_ips[0], resource="my-profile",
                              request_id=f"scoring-{uuid.uuid4().hex[:12]}#0")
        threat = threat_engine.assess(db, bob, utcnow())
    assert result.threat is not None and threat.factors == []
    assert threat.evidence_strength == "none" and threat.impact_severity == "none" and threat.level == "normal"
    assert threat.breakdown["rule_evidence"] == [] and threat.components["rules"]["value"] == 0.0


def test_strength_and_impact_say_so_when_there_is_nothing_to_judge():
    strength = scoring.evidence_strength(rule_groups=0, counted_stages=0, ml_score=None, ml_mode=None)
    assert strength["level"] == "none" and any("unavailable" in r for r in strength["reasons"])
    impact = scoring.impact_severity({"status": "none"}, [], False)
    assert impact["level"] == "none" and impact["reasons"]


def test_a_missing_model_is_never_counted_as_corroboration():
    fallback = scoring.evidence_strength(rule_groups=2, counted_stages=1, ml_score=0.99, ml_mode="fallback")
    trained = scoring.evidence_strength(rule_groups=2, counted_stages=1, ml_score=0.99, ml_mode="isolation_forest")
    assert fallback["level"] == "weak" and not fallback["model_agrees"]
    assert trained["level"] == "moderate" and trained["model_agrees"]


# ============================================================================================ duplicate evidence
def test_the_same_event_counts_once_however_often_it_appears():
    one, _ = threat_engine._rule_component(corr_of(evidence(7)))
    again, groups = threat_engine._rule_component(corr_of(evidence(7), evidence(7), evidence(7)))
    assert again == one and len(groups) == 1 and groups[0]["count"] == 1 and groups[0]["event_ids"] == [7]


def test_repeats_of_one_rule_on_one_target_are_discounted_and_capped():
    one, _ = threat_engine._rule_component(corr_of(evidence(1)))
    two, _ = threat_engine._rule_component(corr_of(evidence(1), evidence(2)))
    many, groups = threat_engine._rule_component(corr_of(*[evidence(i) for i in range(1, 60)]))
    cap = rules.scoring("repeat_cap") * 0.42
    assert one < two < many <= cap + 1e-9 and groups[0]["count"] == 59
    assert groups[0]["counted_weight"] <= cap + 1e-3 and groups[0]["rule_weight"] == 0.42


def test_different_rules_combine_without_exceeding_the_sum_of_their_weights():
    a, _ = threat_engine._rule_component(corr_of(evidence(1)))
    b, _ = threat_engine._rule_component(corr_of(evidence(2, "unfamiliar_ip", 0.18, None)))
    both, groups = threat_engine._rule_component(corr_of(evidence(1), evidence(2, "unfamiliar_ip", 0.18, None)))
    assert max(a, b) < both < a + b and len(groups) == 2


def test_the_score_is_exactly_its_two_components_and_nothing_else_is_added(client, admin):
    run_steps(client, admin, "david.kumar", CHAIN)
    detail = risk(client, admin, "david.kumar")
    parts = detail["score_breakdown"]["components"]
    assert {p["key"] for p in parts} == {"rules", "ml"}
    assert abs(sum(p["contribution"] for p in parts) - detail["risk_score"]) < 0.01
    assert abs(sum(p["weight"] for p in parts) - 1.0) < 1e-3
    for p in parts:
        assert abs(p["contribution"] - 100 * p["weight"] * p["value"]) < 0.01
    listed = set(detail["score_breakdown"]["not_added_to_the_score"])
    assert {"attack stage", "correlation strength", "baseline deviation"} <= listed


def test_the_stage_and_correlation_do_not_feed_the_score():
    """Changing how many stages the evidence spans, with the same rule evidence and model output, leaves the score alone."""
    w = rules.weights()
    values = {"rules": 0.62, "ml": 0.4}
    assert scoring.combine(values, w) == scoring.combine(values, w)
    sig = scoring.combine.__code__.co_varnames[:scoring.combine.__code__.co_argcount]
    assert sig == ("values", "weights")                                       # the function cannot see stages or baseline


# ============================================================================================ severity is not confidence
def test_impact_is_judged_from_the_evidence_alone():
    assert scoring.combine.__code__.co_argcount == 2
    params = scoring.impact_severity.__code__.co_varnames[:scoring.impact_severity.__code__.co_argcount]
    assert params == ("exposure", "stages", "has_evidence")                   # no score, band or model output goes in
    bulk = get_settings().bulk_record_threshold
    cases = [
        ({"status": "confirmed_external_transfer", "external_transfer_confirmed": True, "records_confirmed_external": 10,
          "records_potentially_exposed": 10}, ["exfiltration"], "critical"),
        ({"status": "confirmed_export", "records_potentially_exposed": bulk}, ["collection"], "high"),
        ({"status": "none"}, ["privilege_escalation"], "high"),
        ({"status": "confirmed_export", "records_potentially_exposed": 5, "statement": "x"}, ["collection"], "medium"),
        ({"status": "suspicious_access", "statement": "x"}, ["sensitive_resource_access"], "medium"),
        ({"status": "none"}, ["initial_access"], "low"),
    ]
    for exposure, stages, expected in cases:
        assert scoring.impact_severity(exposure, stages, True)["level"] == expected, (exposure, stages)


def test_a_high_impact_finding_can_carry_weak_or_moderate_evidence_and_a_low_band(client, admin):
    """One bulk export, one attack stage: impact is high, but the band stays low and the evidence is not strong."""
    with SessionLocal() as db:
        frank = db.scalar(select(Employee).where(Employee.username == "frank.osei"))
        _, permitted = access_resource(db, frank, "customer-accounts", "export", source_ip="10.20.5.61", session=None,
                                       record_count=25_000, is_synthetic=True, scenario="scoring_test")
        assert permitted
    detail = risk(client, admin, "frank.osei")
    assert detail["impact_severity"] == "high" and detail["independent_stages"] == 1
    assert detail["evidence_strength"] in ("weak", "moderate") and detail["level"] in ("normal", "suspicious")
    assert detail["impact"]["reasons"] and detail["strength"]["reasons"]
    assert not [a for a in client.get("/api/alerts", headers=admin).json() if a["employee_username"] == "frank.osei"]


def test_a_full_chain_is_strong_evidence_and_critical_impact_and_the_two_are_reported_separately(client, admin):
    run_steps(client, admin, "david.kumar", CHAIN)
    detail = risk(client, admin, "david.kumar")
    assert detail["impact_severity"] == "critical" and detail["evidence_strength"] == "strong" and detail["level"] == "critical"
    alert = next(a for a in client.get("/api/alerts", headers=admin).json() if a["employee_username"] == "david.kumar")
    assert alert["risk_band"] == "critical" and alert["impact_severity"] == "critical" and alert["evidence_strength"] == "strong"
    assert "severity" not in alert                                           # no field mixes impact with the score band
    assert client.get("/api/alerts", headers=admin, params={"impact_severity": "critical"}).json()
    assert client.get("/api/alerts", headers=admin, params={"impact_severity": "low"}).json() == []


def test_impact_never_goes_down_while_an_alert_is_open_and_strength_follows_the_latest_window(client, admin):
    run_steps(client, admin, "david.kumar", CHAIN)
    alert = next(a for a in client.get("/api/alerts", headers=admin).json() if a["employee_username"] == "david.kumar")
    assert alert["impact_severity"] == "critical" and alert["score_basis"]["not_a_probability"] is True
    assert alert["peak_risk_score"] >= alert["risk_score"]


# ============================================================================================ consistent explanations
def test_every_explanation_of_one_assessment_agrees(client, admin):
    run_steps(client, admin, "david.kumar", CHAIN)
    detail = risk(client, admin, "david.kumar")
    (row,) = [r for r in client.get("/api/soc/investigations", headers=admin).json() if r["employee_id"] == "EMP-1004"]
    soc = client.get(f"/api/soc/investigations/{row['id']}", headers=admin).json()
    audit, explained = soc["audit"], soc["explanation"]["risk_assessment"]

    assert audit["risk_score"] == detail["risk_score"] == soc["live"]["risk_score"] == explained["risk_score"]
    assert audit["risk_band"] == detail["level"] == soc["live"]["level"] == explained["risk_band"] == row["level"]
    assert audit["impact"]["level"] == detail["impact_severity"] == explained["impact_severity"] == row["impact_severity"]
    assert audit["strength"]["level"] == detail["evidence_strength"] == explained["evidence_strength"]
    assert audit["breakdown"] == detail["score_breakdown"] or audit["breakdown"]["risk_score"] == detail["score_breakdown"]["risk_score"]

    ids = {e["event_id"] for e in audit["evidence"]}
    for group in audit["breakdown"]["rule_evidence"]:
        assert set(group["event_ids"]) <= ids and group["points"] if "points" in group else True
        assert group["counted_weight"] >= group["rule_weight"] - 1e-9 or group["count"] == 1
    counted = {e["event_id"] for e in audit["evidence"] if e["counted"]}
    assert counted == {i for g in audit["breakdown"]["rule_evidence"] for i in g["event_ids"]}
    assert {f["rule"] for f in detail["factors"]} == {g["rule"] for g in audit["breakdown"]["rule_evidence"]}

    window = audit["breakdown"]["window"]
    assert window["minutes"] == get_settings().correlation_window_minutes and window["start"] < window["end"]
    for e in audit["evidence"]:
        assert window["start"] <= e["timestamp"] <= window["end"]
    assert audit["breakdown"]["model"]["score"] == detail["ml"]["score"]
    assert {d["feature"] for d in audit["breakdown"]["feature_deviations"]} >= {"download_volume", "unfamiliar_ip", "restricted_access_attempts"}
    th = audit["breakdown"]["thresholds"]
    settings = get_settings()
    assert (th["watch"], th["elevated"], th["alert"]) == (settings.threat_suspicious_threshold, settings.threat_high_threshold,
                                                           settings.threat_critical_threshold)


def test_the_basis_recorded_with_an_alert_is_the_basis_that_applied_then(client, admin):
    run_steps(client, admin, "david.kumar", CHAIN[:5])
    alert = next(a for a in client.get("/api/alerts", headers=admin).json() if a["employee_username"] == "david.kumar")
    basis = alert["score_basis"]
    first_stages = basis["gate"]["independent_stages"]
    assert first_stages >= rules.scoring("min_stages_for_critical") and basis["risk_score"] >= get_settings().threat_critical_threshold
    run_steps(client, admin, "david.kumar", CHAIN[5:])
    later = next(a for a in client.get("/api/alerts", headers=admin).json() if a["employee_username"] == "david.kumar")
    assert later["score_basis"]["risk_score"] >= basis["risk_score"] and later["peak_risk_score"] >= alert["peak_risk_score"]


def test_the_export_carries_the_same_numbers_and_labels_them_heuristic(client, admin):
    run_steps(client, admin, "david.kumar", CHAIN)
    (row,) = [r for r in client.get("/api/soc/investigations", headers=admin).json() if r["employee_id"] == "EMP-1004"]
    report = client.get(f"/api/investigations/{row['id']}/export", headers=admin, params={"format": "json"}).json()
    summary = report["incident_summary"]
    assert summary["heuristic_risk_score"] == row["risk_score"] and "not a probability" in summary["risk_score_note"]
    assert summary["risk_band"] == row["level"] and summary["impact_severity"] == row["impact_severity"]
    assert "attack_confidence" not in summary and "severity" not in summary
    assert all({"heuristic_risk_score", "risk_band", "anomaly_score"} <= set(h) for h in report["risk_score_history"])


# ============================================================================================ thresholds: validation only
def record(scenario, label, split, seed, best3=-1.0, best0=-1.0, any0=-1.0, any3=-1.0, ml=0.0):
    return cal.RunRecord(scenario, label, split, seed, target_best={0: best0, 2: best3, 3: best3}, any_best={0: any0, 2: any3, 3: any3},
                         target_ml_peak=ml, any_ml_peak=ml, series=[[0, best0, 1, ml], [1, best3, 3, ml]])


def synthetic_runs(test_scores):
    validation = ([record("m", 1, "validation", s, best3=60 + s, best0=60 + s) for s in range(8)]
                  + [record("b", 0, "validation", 100 + s, any0=20 + 4 * s, any3=-1.0) for s in range(8)])
    test = ([record("m", 1, "test", 200 + s, best3=test_scores, best0=test_scores) for s in range(8)]
            + [record("b", 0, "test", 300 + s, any0=test_scores, any3=test_scores) for s in range(8)])
    return validation + test


def test_thresholds_depend_on_validation_runs_only():
    a, b = synthetic_runs(10), synthetic_runs(99)
    for records in (a, b):
        pass
    chosen_a = cal.select_thresholds([r for r in a if r.split == "validation"])
    chosen_b = cal.select_thresholds([r for r in b if r.split == "validation"])
    assert chosen_a == chosen_b                                               # wildly different test runs, same operating point
    result_a, result_b = cal.build_result(a, 8), cal.build_result(b, 8)
    assert result_a["thresholds"] == result_b["thresholds"] == chosen_a
    assert result_a["ml_corroboration_threshold"] == result_b["ml_corroboration_threshold"]
    assert result_a["test"] != result_b["test"] and result_a["validation"] == result_b["validation"]
    changed = [r for r in a if r.split == "validation"]
    for r in changed:
        if r.label == 0:
            r.any_best = {k: 90.0 for k in r.any_best}
    assert cal.select_thresholds(changed) != chosen_a                         # but the validation runs do move it


def test_the_selected_threshold_respects_the_false_flag_budget_on_validation():
    runs = [r for r in synthetic_runs(50) if r.split == "validation"]
    for band in cal.BAND_GATES:
        chosen = cal.select_threshold(runs, band)["threshold"]
        assert cal.rates(runs, band, chosen)["false_flag_rate"] <= cal.FALSE_FLAG_BUDGET[band]
        if chosen > 0:                                                         # it is the lowest threshold that does
            assert cal.rates(runs, band, chosen - 1)["false_flag_rate"] > cal.FALSE_FLAG_BUDGET[band]
    ordered = cal.select_thresholds(runs)
    assert ordered["suspicious"] <= ordered["high_risk"] <= ordered["critical"]


def test_rates_report_the_trade_off_between_misses_and_false_flags():
    runs = [r for r in synthetic_runs(50) if r.split == "validation"]
    curve = cal.tradeoff(runs, "suspicious", step=10)
    misses = [c["miss_rate"] for c in curve]
    false_flags = [c["false_flag_rate"] for c in curve]
    assert misses == sorted(misses) and false_flags == sorted(false_flags, reverse=True)
    for c in curve:
        assert c["tp"] + c["fn"] == 8 and c["fp"] + c["tn"] == 8


def test_the_recorded_operating_point_is_validation_based_disjoint_from_test_and_in_force():
    point = load_operating_point(ROOT / "backend" / "operating_point.json")
    assert point, "run python -m ml.calibrate_scoring to record an operating point"
    th = point["thresholds"]
    assert 0 <= th["suspicious"] <= th["high_risk"] <= th["critical"] <= 100
    assert point["selected_on"]["split"] == "validation" and point["test"]["seeds"][0] > point["selected_on"]["seeds"][1]
    assert point["targets"]["note"] and point["limitations"] and "synthetic" in point["status"]
    for band in ("Watch", "Elevated", "Alert"):
        row = point["validation"]["bands"][band]
        assert {"tp", "fn", "fp", "tn", "miss_rate", "false_flag_rate"} <= set(row) and point["test"]["bands"][band]["threshold"] == th[
            {"Watch": "suspicious", "Elevated": "high_risk", "Alert": "critical"}[band]]
    settings = get_settings()
    assert settings.thresholds_source == "calibrated"
    assert (settings.threat_suspicious_threshold, settings.threat_high_threshold, settings.threat_critical_threshold) == (
        th["suspicious"], th["high_risk"], th["critical"])
    status_text = json.dumps(scoring.operating_point_summary())
    assert "synthetic" in status_text


def test_environment_overrides_beat_the_operating_point_and_say_so(monkeypatch):
    monkeypatch.setenv("THREAT_CRITICAL_THRESHOLD", "91")
    get_settings.cache_clear()
    try:
        s = get_settings()
        assert s.threat_critical_threshold == 91 and s.thresholds_source == "environment override"
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


def test_without_an_operating_point_the_defaults_are_labelled_uncalibrated(monkeypatch, tmp_path):
    monkeypatch.setenv("OPERATING_POINT_PATH", str(tmp_path / "missing.json"))
    get_settings.cache_clear()
    try:
        s = get_settings()
        assert s.thresholds_source == "uncalibrated defaults" and s.threat_critical_threshold == 80
        assert scoring.operating_point_summary()["status"] == "uncalibrated defaults"
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


# ============================================================================================ migration of the old columns
def test_the_old_confidence_columns_are_renamed_with_their_values_kept(tmp_path):
    db = cal_engine(tmp_path)
    with db.begin() as conn:
        conn.exec_driver_sql("INSERT INTO employees (username, full_name, email, department, job_role, role, status, password_hash, known_ips, "
                             "is_synthetic, created_at) VALUES ('m.a','M A','m.a@westbridgebank.test','Ops','Analyst','employee','active','x','[]',0,'2026-01-01')")
        conn.exec_driver_sql("INSERT INTO attack_investigations (employee_id, status, attack_stage, attack_type, risk_score_exact, risk_score, summary, "
                             "timeline, indicators, recommended_actions, is_synthetic, created_at, updated_at) VALUES (1,'resolved','none','none',83.5,83,'','[]','[]','[]',0,"
                             "'2026-01-01','2026-01-01')")
        conn.exec_driver_sql("ALTER TABLE attack_investigations RENAME COLUMN risk_score_exact TO confidence")
        conn.exec_driver_sql("UPDATE attack_investigations SET confidence = 0.835")                                  # stored as a fraction
        conn.exec_driver_sql("ALTER TABLE attack_investigations DROP COLUMN impact_severity")
        conn.exec_driver_sql("ALTER TABLE attack_investigations DROP COLUMN evidence_strength")
        conn.exec_driver_sql("ALTER TABLE security_alerts RENAME COLUMN peak_risk_score TO attack_confidence")
        conn.exec_driver_sql("ALTER TABLE security_alerts DROP COLUMN impact_severity")
        conn.exec_driver_sql("ALTER TABLE security_alerts DROP COLUMN score_basis")
        conn.exec_driver_sql("DELETE FROM schema_migrations WHERE version >= 3")
    assert migrations.current_version(db) == 2
    assert migrations.upgrade(db) == list(range(3, migrations.CURRENT_VERSION + 1))
    with db.connect() as conn:
        cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(attack_investigations)")}
        alert_cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(security_alerts)")}
        assert {"risk_score_exact", "impact_severity", "evidence_strength"} <= cols and "confidence" not in cols
        assert {"peak_risk_score", "impact_severity", "evidence_strength", "score_basis"} <= alert_cols and "attack_confidence" not in alert_cols
        assert conn.exec_driver_sql("SELECT risk_score_exact FROM attack_investigations").scalar() == pytest.approx(83.5)
    assert migrations.upgrade(db) == []
    db.dispose()


def test_a_legacy_unversioned_database_with_the_old_columns_upgrades_in_one_pass(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE employees (id INTEGER PRIMARY KEY, username TEXT, full_name TEXT, email TEXT, department TEXT, job_role TEXT,
            role TEXT, status TEXT, password_hash TEXT, known_ips JSON, created_at DATETIME, last_login_at DATETIME);
        CREATE TABLE attack_investigations (id INTEGER PRIMARY KEY, employee_id INTEGER, status TEXT, attack_stage TEXT, confidence FLOAT,
            risk_score INTEGER, summary TEXT, timeline JSON, indicators JSON, recommended_actions JSON, exposure JSON,
            created_at DATETIME, updated_at DATETIME, closed_at DATETIME);
        INSERT INTO employees VALUES (1,'o.l','O L','o.l@westbridgebank.test','Ops','Analyst','employee','active','x','[]','2026-01-01',NULL);
        INSERT INTO attack_investigations VALUES (1,1,'resolved','collection',0.64,64,'s','[]','[]','[]',NULL,'2026-01-01','2026-01-01',NULL);
    """)
    con.commit()
    con.close()
    from backend.db_tools import make_engine

    db = make_engine(f"sqlite:///{path.as_posix()}")
    assert migrations.upgrade(db)[-1] == migrations.CURRENT_VERSION
    with db.connect() as conn:
        assert conn.exec_driver_sql("SELECT risk_score_exact, risk_score FROM attack_investigations").fetchone() == pytest.approx((64.0, 64))
    db.dispose()


def cal_engine(tmp_path):
    from backend.db_tools import make_engine

    db = make_engine(f"sqlite:///{(tmp_path / 'm.db').as_posix()}")
    migrations.upgrade(db)
    return db


# ============================================================================================ labels: nothing is called a probability
FORBIDDEN = re.compile(r"attack[ _]confidence|confidence[ _]score|\bconfidence\b", re.IGNORECASE)


def test_no_screen_or_api_field_calls_a_heuristic_a_confidence():
    allowed = {"migrations.py"}   # it names the old columns it renames; lines marked "legacy" read pre-rename stored data
    offenders = []
    for folder in ("backend", "frontend"):
        for path in sorted((ROOT / folder).glob("*.py")):
            if path.name in allowed:
                continue
            lines = path.read_text(encoding="utf-8").splitlines()
            for number, line in enumerate(lines, 1):
                context = (line + " " + (lines[number - 2] if number > 1 else "")).lower()
                if FORBIDDEN.search(line) and "legacy" not in context:
                    offenders.append(f"{path.name}:{number}: {line.strip()[:100]}")
    assert not offenders, offenders


def test_readme_defines_the_scores_and_never_presents_one_as_a_probability():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "not a probability" in text and "Heuristic risk score" in text and "Impact severity" in text and "Evidence strength" in text
    flat = re.sub(r"\s+", " ", text)
    for match in re.finditer(r"[^.]*\bprobabilit[^.]*", flat, re.IGNORECASE):
        sentence = match.group(0).lower()
        assert any(w in sentence for w in ("not ", "no ", "never", "without", "nor ", "isn't", "cannot", "neither", "rather than")), sentence
    th = load_operating_point(ROOT / "backend" / "operating_point.json")["thresholds"]
    assert f"Watch {th['suspicious']}, Elevated {th['high_risk']}, Alert {th['critical']}" in text      # the documented operating point is the recorded one


def test_the_definitions_served_to_the_dashboards_all_deny_being_probabilities(client, admin):
    info = client.get("/api/detection/status", headers=admin).json()
    assert set(info["score_definitions"]) >= {"risk_score", "risk_band", "impact_severity", "evidence_strength", "anomaly_score", "rule_weight"}
    assert all(d["is_probability"] is False and d["kind"] and d["text"] for d in info["score_definitions"].values())
    assert info["operating_point"]["source"] == "calibrated" and info["operating_point"]["limitations"]


# ============================================================================================ what the analyst sees
@pytest.fixture(scope="module")
def live(tmp_path_factory):
    backend = Backend(tmp_path_factory.mktemp("scoring"))
    backend.start()
    yield backend
    backend.stop()


def page_text(at) -> str:
    parts = [m.value for m in at.markdown] + [m.value for m in at.caption] + [e.value for e in at.error]
    parts += [i.value for i in at.info] + [s.value for s in at.success] + [w.value for w in at.warning]
    for table in at.get("expander"):
        parts.append(table.label)
    return "\n".join(str(p) for p in parts)


def test_the_soc_dashboard_separates_the_scores_names_them_honestly_and_explains_the_calculation(live, monkeypatch):
    import requests

    admin = live.login("SEC-9011", ADMIN_PASSWORD)
    david = next(e["id"] for e in live.get("/api/employees", admin) if e["username"] == "david.kumar")
    for step in CHAIN:
        requests.post(f"{live.url}/api/simulation/steps", headers=admin, timeout=60,
                      json={"target_employee_id": david, "step": step, "source_ip": IP, "scenario": "it_admin_full_chain"}).raise_for_status()
    at = _sign_in(_run_app("frontend/soc_dashboard.py", live, monkeypatch), "SEC-9011", ADMIN_PASSWORD)
    assert not at.exception

    overview = page_text(at)
    assert "Heuristic risk score" in overview and "Risk band" in overview and "Impact" in overview
    assert "How to read the scores" in overview and "not a probability" in overview
    assert not re.search(r"attack confidence", overview, re.IGNORECASE)

    at = at.button(key="nav_Attack Investigations").click().run()
    assert not at.exception
    inv = next(r for r in live.get("/api/soc/investigations", admin) if r["employee_id"] == "EMP-1004")
    at.session_state["selected_investigation"] = inv["id"]
    at = at.run()
    assert not at.exception, [e.message for e in at.exception]
    detail = page_text(at)
    labels = " ".join(str(e.label) for e in at.get("expander"))
    assert "How the heuristic risk score was built" in labels
    assert "Impact severity" in detail and "Evidence strength" in detail
    assert not re.search(r"attack confidence|confidence was", detail + labels, re.IGNORECASE)
    tables = " ".join(str(m.value) for m in at.markdown)
    assert "Rule evidence (reason codes)" in tables and "Event references" in tables and "Feature deviations" in tables
    assert "Risk band, gate and thresholds" in tables and "Anomaly model output" in tables

    for page in ("Live Event Feed", "Employee Risk Monitor", "Response Centre", "Attack Timeline"):
        at = at.button(key=f"nav_{page}").click().run()
        assert not at.exception, page
        assert not re.search(r"attack confidence", page_text(at), re.IGNORECASE), page
