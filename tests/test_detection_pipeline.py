"""Detection pipeline: windows, features, hybrid risk, auditability and robustness to messy event streams."""
import random
from datetime import timedelta

import numpy as np
import pandas as pd
import pytest

from ml.cert.leakage import assert_no_leakage
from ml.cert.synthetic import DEFAULT_PROFILE, SyntheticConfig, _Builder
from ml.detect import benchmark, hybrid
from ml.detect.features import (
    DEVIATION_FEATURES,
    FEATURE_COLUMNS,
    PeerBaseline,
    build_features,
    own_baseline_features,
)
from ml.detect.models import IsolationForestModel
from ml.detect.windows import build_windows, prepare_frame

N_USERS, DAYS = 40, 75
BULK, GRADUAL, BENIGN_ONCE, POWER = N_USERS - 1, N_USERS - 2, N_USERS - 3, N_USERS - 4


def _users():
    return [dict(user_id=f"SYN-U{i:04d}", entity_id=f"S{i:04d}", host=f"SYNPC-{i}", file_rate=1.0, usb=False, usb_rate=0.0, start_hour=None)
            for i in range(N_USERS)]


@pytest.fixture(scope="module")
def world():
    cfg = SyntheticConfig(seed=5, n_users=N_USERS, days=DAYS, missing_rate=0.0, typo_logon_rate=0.0)
    b = _Builder(cfg, DEFAULT_PROFILE, random.Random(5))
    users = _users()
    for user in users:
        for d in range(DAYS):
            day = b.start + timedelta(days=d)
            if day.weekday() < 5:
                b.normal_day(user, day)
    b.threat("bulk_export", users[BULK], b.start + timedelta(days=60))                   # Monday-ish, business hours
    b.threat("gradual_data_collection", users[GRADUAL], b.start + timedelta(days=42))
    b.lookalike("legit_large_transfer", users[BENIGN_ONCE], b.start + timedelta(days=60))
    for d in range(2, 72, 4):                                                           # a role that routinely sends large transfers
        b.lookalike("legit_large_transfer", users[POWER], b.start + timedelta(days=d))
    return b, users


@pytest.fixture(scope="module")
def scored(world):
    b, users = world
    frame = pd.DataFrame(b.rows)
    normal = {u["entity_id"] for u in users[: N_USERS - 4]}
    windows = build_windows(frame, train_entities=normal)
    windows["label"] = 0.0
    splits = pd.DataFrame({"entity_id": [u["entity_id"] for u in users],
                           "split": ["train" if u["entity_id"] in normal else "test" for u in users]})
    w, F, benign_train, ready = benchmark.prepare_frames(windows, splits, None)
    anomaly = IsolationForestModel(DEVIATION_FEATURES, name="t", n_estimators=100).fit(F[benign_train])
    result = hybrid.score_hybrid(F, anomaly.score(F), w["entity_id"], w["day"])
    ordinary = benign_train & ready
    theta = float(np.quantile(result.risk[ordinary], 0.995))
    return dict(frame=frame, w=w, F=F, result=result, theta=theta, ready=ready, users=users)


def _rows(scored, index):
    w = scored["w"]
    mask = (w["entity_id"] == scored["users"][index]["entity_id"]).to_numpy() & scored["ready"]
    return mask


def test_malicious_bulk_export_sequence_is_alerted_with_correlated_reason_codes(scored):
    mask = _rows(scored, BULK)
    risk = scored["result"].risk
    peak = int(np.argmax(np.where(mask, risk, -1)))
    assert risk[peak] > scored["theta"], (risk[peak], scored["theta"])
    explanation = hybrid.explain(scored["F"].iloc[peak], scored["result"], peak)
    families = {c["family"] for c in explanation["reason_codes"]}
    assert "collection" in families and len(families) >= 2          # collection plus corroboration, not a single rule
    assert explanation["states"]["suspicious_sequence"] and explanation["states"]["potential_data_exposure"]
    assert not explanation["states"].get("confirmed")              # a model output is never "confirmed"


def test_benign_one_off_large_transfer_is_not_a_correlated_sequence_or_critical(scored):
    mask = _rows(scored, BENIGN_ONCE)
    result, w = scored["result"], scored["w"]
    attack = result.risk[_rows(scored, BULK)].max()
    assert result.risk[mask].max() < 0.6 * attack, (result.risk[mask].max(), attack)       # far below a real bulk-export sequence
    assert not result.states.loc[mask, "suspicious_sequence"].any()                         # one signal is never a correlated sequence
    transfer_day = mask & (w["email_bytes_external"] > 1e7).to_numpy()
    assert transfer_day.any()
    assert (result.active.loc[transfer_day, "transfer"] <= 1.0).all()
    ceiling = 1 - (1 - hybrid.FAMILY_WEIGHTS["transfer"]) * (1 - hybrid.FAMILY_WEIGHTS["timing"]) * (1 - hybrid.FAMILY_WEIGHTS["anomaly"])
    assert result.risk[transfer_day].max() <= ceiling + 1e-9                               # bounded by what these families can add up to


def test_routine_large_transfers_by_the_same_user_stay_quiet(scored):
    mask = _rows(scored, POWER)
    w, risk = scored["w"], scored["result"].risk
    transfer_days = mask & (w["email_bytes_external"] > 1e7).to_numpy()
    assert transfer_days.sum() >= 5
    naive_alerts = int(transfer_days.sum())                                        # a fixed "large transfer = alert" rule fires on every one
    ours = int((risk[transfer_days] > scored["theta"]).sum())
    assert ours <= max(2, naive_alerts // 5), (ours, naive_alerts)
    attack = risk[_rows(scored, BULK)].max()
    assert risk[transfer_days].max() < 0.6 * attack                                # far below a real bulk-export sequence


def test_gradual_exfiltration_risk_rises_over_the_campaign(scored):
    mask = _rows(scored, GRADUAL)
    w, risk, active = scored["w"], scored["result"].risk, scored["result"].active
    start = w["day"].min()
    campaign = mask & (w["day"] >= start + pd.Timedelta(days=42)).to_numpy() & (w["day"] <= start + pd.Timedelta(days=64)).to_numpy()
    assert campaign.sum() >= 8
    early, late = np.where(campaign)[0][:4], np.where(campaign)[0][-4:]
    assert risk[late].mean() > risk[early].mean()
    assert active["collection"].to_numpy()[late].max() > active["collection"].to_numpy()[early].max()
    assert risk[campaign].max() > scored["theta"]                    # alerted during the campaign, at the end of the day it crosses
    final_day = w.loc[mask, "day"].max()
    first_alert_day = w.loc[campaign & (risk > scored["theta"]), "day"].min()
    assert first_alert_day <= final_day


def test_missing_fields_and_unusable_rows_do_not_crash_or_invent_data(world, scored):
    b, users = world
    frame = pd.DataFrame(b.rows)
    rng = np.random.default_rng(0)
    for column in ("host", "destination", "bytes", "attachment_count"):
        frame.loc[rng.random(len(frame)) < 0.15, column] = np.nan
    frame.loc[rng.random(len(frame)) < 0.01, "timestamp_utc"] = None
    frame.loc[rng.random(len(frame)) < 0.01, "entity_id"] = None
    frame = frame.drop(columns=["auth_result", "removable_media"])                      # whole optional columns absent
    windows = build_windows(frame, train_entities={u["entity_id"] for u in users[: N_USERS - 4]})
    assert windows["n_events"].sum() > 0 and windows["n_incomplete_events"].sum() > 0
    assert not windows[["n_web", "n_events", "n_file_access", "email_bytes_total"]].isna().any().any()
    prepared = prepare_frame(frame)
    assert len(prepared) < len(frame) and prepared["_ts"].notna().all() and prepared["entity_id"].notna().all()
    windows["label"] = 0.0
    splits = pd.DataFrame({"entity_id": [u["entity_id"] for u in users], "split": ["train"] * N_USERS})
    w, F, bt, ready = benchmark.prepare_frames(windows, splits, None)
    assert np.isfinite(F[FEATURE_COLUMNS].to_numpy()).all()
    result = hybrid.score_hybrid(F, np.zeros(len(F)), w["entity_id"], w["day"])
    mask = (w["entity_id"] == users[BULK]["entity_id"]).to_numpy() & ready
    assert result.risk[mask].max() > 0.3                              # the attack is still visible through the missing values


def test_duplicate_events_do_not_change_windows_or_risk(world, scored):
    b, users = world
    frame = pd.DataFrame(b.rows)
    train = {u["entity_id"] for u in users[: N_USERS - 4]}
    once = build_windows(frame, train_entities=train)
    doubled = pd.concat([frame, frame.sample(frac=0.3, random_state=1), frame.iloc[:2000]], ignore_index=True)
    twice = build_windows(doubled, train_entities=train)
    pd.testing.assert_frame_equal(once, twice)


def test_events_arriving_out_of_order_give_identical_windows_and_features(world):
    b, users = world
    frame = pd.DataFrame(b.rows)
    train = {u["entity_id"] for u in users[: N_USERS - 4]}
    ordered = build_windows(frame, train_entities=train)
    shuffled = build_windows(frame.sample(frac=1.0, random_state=9).reset_index(drop=True), train_entities=train)
    pd.testing.assert_frame_equal(ordered, shuffled)
    pd.testing.assert_frame_equal(own_baseline_features(ordered), own_baseline_features(shuffled))


def test_features_use_only_past_data(world):
    b, users = world
    frame = pd.DataFrame(b.rows)
    train = {u["entity_id"] for u in users[: N_USERS - 4]}
    full = build_windows(frame, train_entities=train)
    cutoff = pd.Timestamp(b.start).tz_localize(None) + pd.Timedelta(days=50)
    prepared = prepare_frame(frame)
    partial = build_windows(frame[prepared.reindex(frame.index)["_ts"] < cutoff], train_entities=train)
    f_full, f_part = own_baseline_features(full), own_baseline_features(partial)
    f_full["_k"] = full["entity_id"] + full["day"].astype(str)
    f_part["_k"] = partial["entity_id"] + partial["day"].astype(str)
    shared = f_full.merge(f_part, on="_k", suffixes=("_f", "_p"))
    assert len(shared) > 500
    for column in ("z_own_n_file_access", "z_own_n_web", "start_hour_dev_own"):
        np.testing.assert_allclose(shared[f"{column}_f"], shared[f"{column}_p"], atol=1e-9)   # the future never changes the past


def test_every_family_counts_once_and_risk_is_bounded(scored):
    result = scored["result"]
    for family in hybrid.FAMILIES:
        codes = [r.code for r in hybrid.RULES if r.family == family and r.code in result.rules]
        if family != "anomaly":
            np.testing.assert_allclose(result.daily[family].to_numpy(), result.rules[codes].max(axis=1).to_numpy())   # max, not sum
    assert (result.risk >= 0).all() and (result.risk <= 1).all()
    ceiling = 1 - np.prod([1 - w for w in hybrid.FAMILY_WEIGHTS.values()])
    assert result.risk.max() <= ceiling + 1e-9
    assert (result.daily["anomaly"] <= 1 - result.daily.drop(columns="anomaly").max(axis=1) + 1e-9).all()   # anomaly net of rule evidence


def test_explanation_is_auditable_and_never_claims_confirmation(scored):
    result, F = scored["result"], scored["F"]
    peak = int(np.argmax(result.risk))
    audit = hybrid.explain(F.iloc[peak], result, peak, evidence={"first_event_ts": "2010-01-01T08:00:00"})
    assert {"risk", "reason_codes", "family_contributions", "states", "note", "evidence"} <= set(audit)
    assert all({"code", "family", "strength", "description"} <= set(c) for c in audit["reason_codes"])
    assert {c["family"] for c in audit["family_contributions"]} == set(hybrid.FAMILY_WEIGHTS)
    assert set(audit["states"]) == {"anomalous_activity", "suspicious_sequence", "potential_data_exposure"}
    assert "never confirmations" in audit["note"]
    recomputed = 1 - np.prod([1 - c["weight"] * c["strength_after_decay"] for c in audit["family_contributions"]])
    assert abs(recomputed - audit["risk"]) < 1e-3                       # the displayed weights and strengths reproduce the risk


def test_features_contain_no_labels_or_identities(scored):
    assert_no_leakage(FEATURE_COLUMNS)
    w = scored["w"].copy()
    w["label"] = 1.0
    w["scenario"] = "bulk_export"
    peer = PeerBaseline().fit(scored["F"], pd.Series("all", index=scored["F"].index))
    again = build_features(w, peer)
    base = build_features(scored["w"], peer)
    pd.testing.assert_frame_equal(again[FEATURE_COLUMNS], base[FEATURE_COLUMNS])     # changing labels cannot change features


def test_thresholds_come_from_validation_and_test_can_only_be_evaluated_once(tmp_path):
    from ml.cert import synthetic

    processed = tmp_path / "syn"
    synthetic.generate(processed, synthetic.SyntheticConfig(seed=3, n_users=80, days=70))
    out = tmp_path / "reports"
    with pytest.raises(SystemExit, match="needs --final"):
        benchmark.run("synthetic", processed, "test", final=False, force=False, out_dir=out, log=lambda *_: None)
    first = benchmark.run("synthetic", processed, "test", final=True, force=False, out_dir=out, log=lambda *_: None)
    with pytest.raises(SystemExit, match="already evaluated"):
        benchmark.run("synthetic", processed, "test", final=True, force=False, out_dir=out, log=lambda *_: None)
    assert first["final_test_run"] and "validation" in first["operating_point"].lower()
    for model in first["models"].values():
        assert model["threshold_calibrated_on_validation"] is not None
        assert set(model["recall_at_validation_fpr"]) == {"0.001", "0.005", "0.01"}
