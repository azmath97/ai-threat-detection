"""Machine-learning layer, dataset, rules configuration and thresholds."""
import copy
from dataclasses import replace
from pathlib import Path

import pytest

from backend import detection_engine, rules
from backend.config import get_settings
from ml.anomaly_detector import AnomalyDetector, heuristic_score
from ml.features import FEATURE_NAMES, Baseline, EventRecord, extract_features
from ml.synthetic_data import ATTACK_KINDS, generate_dataset, window_features
from ml.train_model import train


@pytest.fixture(scope="module")
def dataset():
    return generate_dataset(seed=7, n_employees=24)


def test_synthetic_dataset_covers_required_behaviours(dataset):
    events = [e for w in dataset.windows for e in w.events]
    types = {e.event_type for e in events}
    assert {"login", "login_failed", "logout", "resource_access", "file_download", "external_transfer",
            "administrative_action"} <= types
    assert {w.scenario for w in dataset.windows if w.label == 1} == set(ATTACK_KINDS)
    assert any(w.scenario == "after_hours_only" for w in dataset.windows)          # after-hours logins
    normal = [w for w in dataset.windows if w.label == 0]
    assert len(normal) > 500 and sum(w.label for w in dataset.windows) > 100         # enough to train and test
    assert any(e.outcome == "denied" for e in events)                                # restricted access attempts
    assert max(e.records_downloaded for w in normal for e in w.events if e.event_type == "file_download") < 500
    assert max(e.records_downloaded for w in dataset.windows if w.label for e in w.events) > 2000
    assert all(emp.id.startswith("SYN-") for emp in dataset.employees.values())     # no real identities
    ips = {e.source_ip for e in events}
    assert any(ip.startswith("10.") for ip in ips) and any(ip.startswith(("198.51.", "203.0.", "192.0.")) for ip in ips)


def test_model_trains_on_normal_activity_only_and_is_reused(tmp_path):
    path = tmp_path / "model.joblib"
    metrics = train(path, n_employees=20, n_estimators=100, seed=3)
    assert path.exists() and metrics["roc_auc"] > 0.9 and metrics["attack_recall"] > 0.6
    assert metrics["normal_false_positive_rate"] < 0.10
    first = AnomalyDetector(path)
    assert first.available and first.status()["trained_on"].endswith("normal employee sessions only")
    assert first.status()["n_training_windows"] > 300
    # a new detector (application restart) loads the file instead of retraining
    mtime = path.stat().st_mtime
    again = AnomalyDetector(path)
    assert again.available and path.stat().st_mtime == mtime
    data = generate_dataset(seed=3, n_employees=20)
    normal = next(w for w in data.windows if w.label == 0 and w.split == "test")
    attack = next(w for w in data.windows if w.scenario == "full_chain")
    assert again.score(window_features(data, attack)).score > 0.8 > 0.5 > again.score(window_features(data, normal)).score


def test_fallback_mode_when_model_is_unavailable(tmp_path, dataset):
    detector = AnomalyDetector(tmp_path / "missing.joblib")
    assert not detector.available and detector.status()["mode"] == "fallback" and "not found" in detector.status()["error"]
    corrupt = tmp_path / "corrupt.joblib"
    corrupt.write_bytes(b"not a model")
    assert AnomalyDetector(corrupt).status()["mode"] == "fallback"
    normal = next(w for w in dataset.windows if w.label == 0)
    attack = next(w for w in dataset.windows if w.scenario == "full_chain")
    low, high = detector.score(window_features(dataset, normal)), detector.score(window_features(dataset, attack))
    assert low.mode == high.mode == "fallback" and low.score < 0.3 and high.score > 0.8
    assert 0.0 <= heuristic_score({name: 0.0 for name in FEATURE_NAMES}) < 0.01


def test_feature_pipeline_is_consistent_and_uses_all_required_features(dataset):
    assert FEATURE_NAMES == ["login_hour", "unfamiliar_ip", "failed_login_count", "resources_accessed",
                             "departments_accessed", "download_volume", "restricted_access_attempts",
                             "privilege_escalation", "external_transfer_volume", "denied_access_count"]
    window = next(w for w in dataset.windows if w.scenario == "full_chain")
    one = window_features(dataset, window)
    assert one == extract_features(list(window.events), dataset.baselines[window.employee_id])  # deterministic
    assert one["unfamiliar_ip"] == 1 and one["failed_login_count"] >= 8 and one["privilege_escalation"] in (0.0, 1.0)
    assert one["external_transfer_volume"] > 8 and one["restricted_access_attempts"] >= 3
    empty = extract_features([], Baseline())
    assert set(empty) == set(FEATURE_NAMES)


def test_thresholds_are_configurable(monkeypatch):
    settings = get_settings()
    assert [detection_engine.level_for(s) for s in (0, 24.9, 25, 49.9, 50, 79.9, 80, 100)] == [
        "normal", "normal", "suspicious", "suspicious", "high_risk", "high_risk", "critical", "critical"]
    custom = replace(settings, threat_suspicious_threshold=10, threat_high_threshold=30, threat_critical_threshold=90)
    monkeypatch.setattr(detection_engine, "get_settings", lambda: custom)
    assert [detection_engine.level_for(s) for s in (9, 10, 30, 89, 90)] == [
        "normal", "suspicious", "high_risk", "high_risk", "critical"]


def test_rules_are_configurable(monkeypatch):
    base = copy.deepcopy(rules._raw())
    assert abs(sum(rules.weights().values()) - 1.0) < 1e-9
    modified = copy.deepcopy(base)
    modified["rules"]["unfamiliar_ip"]["enabled"] = False
    modified["rules"]["large_export"]["severity"] = 0.9
    monkeypatch.setattr(rules, "_raw", lambda: modified)
    rules.rules.cache_clear()
    try:
        assert not rules.rule("unfamiliar_ip").enabled and rules.rule("large_export").severity == 0.9
    finally:
        monkeypatch.undo()
        rules.rules.cache_clear()
    assert rules.rule("unfamiliar_ip").enabled
    assert Path(get_settings().detection_rules_path).exists()
