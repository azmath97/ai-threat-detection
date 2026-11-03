"""The evaluation protocol must fail loudly on leakage, and its outputs must be complete and honest."""
import json
from argparse import Namespace
from dataclasses import replace

import numpy as np
import pandas as pd
import pytest

from ml.cert import synthetic
from ml.cert.leakage import LeakageError
from ml.detect import guards, scenarios
from ml.detect.dataset import build_cert_windows
from ml.detect.evaluate import blind_partition, fit_and_calibrate, run_track
from ml.detect.features import FEATURE_COLUMNS, RAW_FEATURES, own_baseline_features
from ml.detect.protocol import Protocol, assign_partitions
from ml.detect.run_evaluation import run


def _args(out, **overrides):
    base = dict(out=str(out), partition="test", final=True, force=False, seed=42, no_categories=False, skip_cert=True, skip_synthetic=True,
                skip_unit=False, cert_processed=str(out / "none"), synthetic_processed=str(out / "none"), synthetic_seed=2026, unit_seed=5,
                command="python -m ml.detect.run_evaluation --skip-cert --skip-synthetic --partition test --final")
    base.update(overrides)
    return Namespace(**base)


@pytest.fixture(scope="module")
def unit_world():
    return scenarios.build_unit_world(seed=5)


@pytest.fixture(scope="module")
def final_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("evaluation")
    return out, run(_args(out), log=lambda *_: None)


# ---- answer-key fields can never reach a model ------------------------------------------------------------------

@pytest.mark.parametrize("leaky", ["label", "scenario", "n_malicious_events", "first_malicious_ts", "insider_user", "is_insider", "incident_file"])
def test_answer_key_columns_are_rejected_as_model_inputs(leaky):
    columns = list(FEATURE_COLUMNS) + [leaky]
    with pytest.raises(LeakageError):
        guards.assert_model_inputs_clean({"supervised_gbm_reference": columns}, columns)


def test_label_and_identity_columns_in_the_feature_frame_are_rejected():
    with pytest.raises(LeakageError, match="label"):
        guards.assert_model_inputs_clean({"m": RAW_FEATURES}, list(FEATURE_COLUMNS) + ["label"])
    with pytest.raises(LeakageError, match="entity_id"):
        guards.assert_model_inputs_clean({"m": RAW_FEATURES}, list(FEATURE_COLUMNS) + ["entity_id"])


def test_the_documented_feature_set_passes_the_guard():
    guards.assert_model_inputs_clean({"m": RAW_FEATURES, "all": list(FEATURE_COLUMNS)}, FEATURE_COLUMNS)


def test_a_feature_that_copies_the_label_is_caught_by_value():
    rng = np.random.default_rng(0)
    y = (rng.random(400) < 0.1).astype(int)
    honest = pd.DataFrame({"noise": rng.normal(size=400), "signal": y * 0.5 + rng.normal(size=400)})
    guards.assert_no_single_feature_leak(honest, y)
    leaky = honest.assign(innocent_looking_name=y * 3.0 + 1.0)
    with pytest.raises(LeakageError, match="innocent_looking_name"):
        guards.assert_no_single_feature_leak(leaky, y)


def test_features_do_not_depend_on_labels_in_the_evaluated_partition(unit_world):
    w, _ = assign_partitions(unit_world.windows, unit_world.splits, unit_world.incidents, None, None)
    corrupted = w.copy()
    corrupted["label"] = 1.0 - corrupted["label"]
    a = own_baseline_features(w)
    b = own_baseline_features(corrupted)
    pd.testing.assert_frame_equal(a, b)


def test_fit_and_thresholds_ignore_the_labels_of_the_evaluated_partition(unit_world):
    protocol = Protocol(seed=42)
    w, _ = assign_partitions(unit_world.windows, unit_world.splits, unit_world.incidents, None, None)
    ready = own_baseline_features(w)["baseline_ready"].to_numpy() > 0
    corrupted = w.copy()
    test_rows = (corrupted["partition"] == "test").to_numpy()
    corrupted.loc[test_rows, "label"] = 1.0 - corrupted.loc[test_rows, "label"]
    corrupted.loc[test_rows, "n_malicious_events"] = 99.0
    first = fit_and_calibrate(blind_partition(w, "test"), None, ready, protocol, t1=None, t2=None, log=lambda *_: None)
    second = fit_and_calibrate(blind_partition(corrupted, "test"), None, ready, protocol, t1=None, t2=None, log=lambda *_: None)
    assert first.thresholds == second.thresholds
    assert first.skipped == second.skipped


# ---- synthetic records can never enter the CERT held-out set ----------------------------------------------------

@pytest.fixture()
def cert_like_dir(tmp_path):
    """A tiny directory shaped like the prepared CERT release, built from generator rows relabelled as CERT."""
    gen = tmp_path / "gen"
    synthetic.generate(gen, synthetic.SyntheticConfig(seed=3, n_users=30, days=30))
    events = pd.read_csv(gen / "events_synthetic_test.csv.gz")
    events = events[events["event_type"] != "web_visit"].assign(source="cert_r4.2", is_synthetic=False)
    processed = tmp_path / "cert"
    processed.mkdir()
    events.to_csv(processed / "events_logon.csv.gz", index=False)
    pd.read_csv(gen / "splits.csv").to_csv(processed / "splits.csv", index=False)
    return processed


def test_a_clean_cert_directory_builds_windows(cert_like_dir):
    windows = build_cert_windows(cert_like_dir, log=lambda *_: None)
    assert len(windows) > 0


def test_a_synthetic_flagged_record_in_the_cert_files_stops_the_build(cert_like_dir):
    path = cert_like_dir / "events_logon.csv.gz"
    events = pd.read_csv(path)
    events.loc[events.index[0], "is_synthetic"] = True
    events.to_csv(path, index=False)
    with pytest.raises(LeakageError, match="synthetic"):
        build_cert_windows(cert_like_dir, log=lambda *_: None)


def test_a_record_from_another_source_in_the_cert_files_stops_the_build(cert_like_dir):
    path = cert_like_dir / "events_logon.csv.gz"
    events = pd.read_csv(path)
    events.loc[events.index[:3], "source"] = "synthetic_test"
    events.to_csv(path, index=False)
    with pytest.raises(LeakageError, match="another source"):
        build_cert_windows(cert_like_dir, log=lambda *_: None)


def test_cert_source_verification_refuses_mixed_files(cert_like_dir):
    from ml.detect.run_evaluation import verify_cert_sources

    assert verify_cert_sources(cert_like_dir)["synthetic_rows"] == 0
    path = cert_like_dir / "events_logon.csv.gz"
    events = pd.read_csv(path)
    events.loc[events.index[0], ["source", "is_synthetic"]] = ["synthetic_test", True]
    events.to_csv(path, index=False)
    with pytest.raises(SystemExit, match="not CERT"):
        verify_cert_sources(cert_like_dir)


def test_cert_and_synthetic_entities_must_be_disjoint():
    guards.assert_disjoint_entities({"U1", "U2"}, {"S1", "S2"})
    with pytest.raises(LeakageError):
        guards.assert_disjoint_entities({"U1", "S2"}, {"S1", "S2"})


# ---- partitions ---------------------------------------------------------------------------------------------------

def test_partitions_are_user_disjoint_and_time_ordered():
    days = pd.date_range("2010-01-01", periods=100)
    rows = [(f"U{i}", d) for i in range(30) for d in days]
    w = pd.DataFrame(rows, columns=["entity_id", "day"])
    w["label"] = 0.0
    w["scenario"] = None
    w["benign_scenario"] = None
    w["n_malicious_events"] = 0.0
    splits = pd.DataFrame({"entity_id": [f"U{i}" for i in range(30)], "split": ["train"] * 18 + ["validation"] * 6 + ["test"] * 6})
    t1, t2 = days[44], days[64]
    parted, _ = assign_partitions(w, splits, pd.DataFrame(columns=["entity_id", "scenario", "event_ts"]), t1, t2)
    guards.assert_partitions_clean(parted, t1, t2)
    broken = parted.copy()
    broken.loc[(broken["entity_id"] == "U0") & (broken["partition"] == "train"), "entity_id"] = "U20"
    with pytest.raises(LeakageError, match="both"):
        guards.assert_partitions_clean(broken, t1, t2)
    late = parted.copy()
    late.loc[late.index[(late["partition"] == "train")][0], "day"] = days[80]
    with pytest.raises(LeakageError, match="train window"):
        guards.assert_partitions_clean(late, t1, t2)


def test_incidents_straddling_a_cutoff_are_excluded_not_half_used():
    days = pd.date_range("2010-01-01", periods=100)
    w = pd.DataFrame({"entity_id": "U0", "day": days})
    w["label"] = [1.0 if 40 <= i <= 50 else 0.0 for i in range(100)]
    w["scenario"] = np.where(w["label"] == 1, "2", None)
    w["benign_scenario"] = None
    w["n_malicious_events"] = w["label"] * 5
    incidents = pd.DataFrame({"entity_id": "U0", "scenario": "2", "event_ts": [days[40], days[50]]})
    splits = pd.DataFrame({"entity_id": ["U0"], "split": ["train"]})
    parted, status = assign_partitions(w, splits, incidents, days[44], days[64])
    assert "straddles_train_cutoff" in set(status["status"])
    inside = parted["day"].between(days[40], days[50])
    assert parted.loc[inside, "exclude_supervised"].all()           # not used to train the supervised reference

    splits = pd.DataFrame({"entity_id": ["U0"], "split": ["test"]})
    parted, status = assign_partitions(w, splits, incidents, days[30], days[45])
    assert "straddles_test_cutoff" in set(status["status"])
    assert parted.loc[inside & (parted["day"] > days[45]), "exclude_eval"].all()     # not scored as a test incident


# ---- outputs ----------------------------------------------------------------------------------------------------

def test_final_run_writes_json_csv_and_markdown(final_run):
    out, results = final_run
    for name in ("results.json", "manifest.json", "report.md", "final_evaluation.json", "unit_scenarios_models.csv", "unit_scenarios_thresholds.csv"):
        assert (out / name).exists(), name
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    for key in ("protocol", "software", "git", "hybrid_config_sha256", "command", "notes"):
        assert key in manifest
    assert {"python", "numpy", "pandas", "scikit-learn"} <= set(manifest["software"])
    assert manifest["protocol"]["seed"] == 42
    track = results["tracks"]["unit_scenarios"]
    assert track["evaluated_partition"] == "test" and not track["development_run"]
    for key in ("dataset", "partitions", "thresholds", "model_configuration", "features", "models", "incident_status", "split_strategy"):
        assert key in track


def test_report_states_limitations_and_never_gives_a_combined_score(final_run):
    out, _ = final_run
    text = (out / "report.md").read_text(encoding="utf-8")
    assert "No combined score" in text
    assert "not real banking data" in text.lower()
    assert "Limitations" in text and "dense needles" in text
    for forbidden in ("overall score", "headline score", "combined f1", "average f1"):
        assert forbidden not in text.lower().replace("no combined score", "")


def test_tracks_report_separately_with_their_own_metrics(final_run):
    _, results = final_run
    assert set(results["tracks"]) == {"unit_scenarios"}
    models = results["tracks"]["unit_scenarios"]["models"]
    assert {"existing_iforest_raw", "baseline_fixed_rules", "hybrid"} <= set(models)
    for result in models.values():
        assert {"window_level", "event_level", "user_level"} <= set(result)


def test_unit_track_holds_out_only_the_scenario_users(final_run, unit_world):
    _, results = final_run
    parts = results["tracks"]["unit_scenarios"]["partitions"]
    assert parts["test"]["users"] == 4
    assert parts["train"]["malicious_windows"] == 0 and parts["validation"]["malicious_windows"] == 0


def test_the_test_partition_needs_final_and_can_run_once_per_output_directory(tmp_path):
    with pytest.raises(SystemExit, match="needs --final"):
        run(_args(tmp_path / "a", final=False), log=lambda *_: None)
    out = tmp_path / "b"
    out.mkdir()
    (out / "final_evaluation.json").write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit, match="already evaluated"):
        run(_args(out), log=lambda *_: None)


def test_protocol_is_immutable_defaults_use_a_fixed_seed():
    assert Protocol().seed == 42
    assert replace(Protocol(), seed=7).seed == 7 and Protocol().seed == 42
