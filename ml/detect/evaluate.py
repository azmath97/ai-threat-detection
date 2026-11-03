"""One evaluation track: partitions, fitting on train, calibration on validation, evaluation on the held-out partition.

Nothing in `fit_and_calibrate` can see the evaluated partition: it receives only train and validation windows. Features for
every window are causal (each window uses only its own user's earlier days), the peer baseline, domain statistics,
models and thresholds come from train (and validation for thresholds, benign windows only).
"""
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from ml.detect import hybrid
from ml.detect.baselines import FixedRuleBaseline
from ml.detect.benchmark import _round, _scenario_key, bootstrap_ci, confusion, incident_results, summarise_incidents, threshold_for_fpr
from ml.detect.features import (
    DEVIATION_FEATURES,
    FEATURE_COLUMNS,
    OWN_FEATURES,
    RAW_FEATURES,
    PeerBaseline,
    build_features,
    own_baseline_features,
    peer_groups,
)
from ml.detect.guards import assert_model_inputs_clean, assert_no_single_feature_leak, assert_partitions_clean
from ml.detect.models import IsolationForestModel, LocalOutlierFactorModel, RobustZModel, SupervisedReference
from ml.detect.protocol import Protocol, assign_partitions, cutoffs

# Names used in every report. "existing" = the original approach (Isolation Forest on raw per-day volumes).
MODEL_ROLES = {
    "baseline_fixed_rules": "simple baseline rules (fixed thresholds, no model)",
    "existing_iforest_raw": "existing detector: Isolation Forest on raw volumes",
    "robust_z_own": "simple baseline: own-history z-scores",
    "iforest_deviation": "improved: Isolation Forest on deviation features",
    "lof_deviation": "improved alternative: Local Outlier Factor",
    "rules_correlation": "improved: rules + correlation, no model",
    "hybrid": "improved: rules + correlation + anomaly model",
    "supervised_gbm_reference": "reference ceiling: supervised, uses labels",
}


@dataclass
class Fitted:
    features: pd.DataFrame
    models: dict
    baseline: FixedRuleBaseline
    thresholds: dict
    peer: PeerBaseline
    skipped: dict


def _masks(w: pd.DataFrame, ready: np.ndarray, part: str) -> np.ndarray:
    return ready & (w["partition"] == part).to_numpy() & w["label"].notna().to_numpy() & ~w["exclude_eval"].to_numpy()


def fit_and_calibrate(w: pd.DataFrame, attributes, ready_all: np.ndarray, protocol: Protocol, *, t1, t2, log=print) -> Fitted:
    """Fit everything on the train partition and calibrate thresholds on validation. `w` may NOT be used for the test labels."""
    own = own_baseline_features(w)
    ready = own["baseline_ready"].to_numpy() > 0
    train = ready & (w["partition"] == "train").to_numpy()
    benign_train = train & (w["label"] == 0).to_numpy()
    peer = PeerBaseline().fit(own[benign_train], peer_groups(w, attributes)[benign_train])
    F = build_features(w, peer, attributes)
    models = {
        "existing_iforest_raw": IsolationForestModel(RAW_FEATURES, name="existing_iforest_raw", seed=protocol.seed).fit(F[benign_train]),
        "iforest_deviation": IsolationForestModel(DEVIATION_FEATURES, name="iforest_deviation", seed=protocol.seed).fit(F[benign_train]),
        "lof_deviation": LocalOutlierFactorModel(DEVIATION_FEATURES, seed=protocol.seed).fit(F[benign_train]),
        "robust_z_own": RobustZModel([c for c in OWN_FEATURES if c.startswith("z_own_")]).fit(F[benign_train]),
    }
    skipped = {}
    labelled_train = train & w["label"].notna().to_numpy() & ~w["exclude_supervised"].to_numpy()
    y_train = w.loc[labelled_train, "label"].to_numpy().astype(int)
    assert_model_inputs_clean({"existing_iforest_raw": RAW_FEATURES, "iforest_deviation": DEVIATION_FEATURES,
                               "supervised_gbm_reference": FEATURE_COLUMNS}, F.columns)
    assert_no_single_feature_leak(F.loc[labelled_train, FEATURE_COLUMNS], y_train)
    if y_train.sum() >= protocol.min_supervised_positives and (y_train == 0).sum() > 0:
        models["supervised_gbm_reference"] = SupervisedReference(FEATURE_COLUMNS, protocol.seed).fit(F[labelled_train], y_train)
    else:
        skipped["supervised_gbm_reference"] = f"only {int(y_train.sum())} labelled malicious train windows (minimum {protocol.min_supervised_positives})"
    baseline = FixedRuleBaseline().fit(w.loc[benign_train])
    # thresholds: benign validation windows only
    val = _masks(w, ready, "validation")
    y_val = w.loc[val, "label"].to_numpy()
    scores = score_models(models, baseline, F, w)[0]
    thresholds = {}
    for name, s in scores.items():
        if name == "baseline_fixed_rules":
            thresholds[name] = {"kind": "fixed", "value": 1.0, **{f"fpr_{f}": None for f in protocol.fpr_points}}
            continue
        thresholds[name] = {"kind": "validation_quantile", "target_fpr": protocol.target_fpr,
                            "value": threshold_for_fpr(s[val], y_val, protocol.target_fpr),
                            **{f"fpr_{f}": threshold_for_fpr(s[val], y_val, f) for f in protocol.fpr_points}}
    thresholds["_validation_benign_windows"] = int((y_val == 0).sum())
    return Fitted(F, models, baseline, thresholds, peer, skipped)


def score_models(models: dict, baseline: FixedRuleBaseline, F: pd.DataFrame, w: pd.DataFrame):
    scores = {name: m.score(F) for name, m in models.items() if name != "supervised_gbm_reference"}
    if "supervised_gbm_reference" in models:
        scores["supervised_gbm_reference"] = models["supervised_gbm_reference"].score(F)
    result = hybrid.score_hybrid(F, scores["iforest_deviation"], w["entity_id"], w["day"])
    scores["rules_correlation"] = hybrid.rules_only_risk(F, w["entity_id"], w["day"])
    scores["hybrid"] = result.risk
    scores["baseline_fixed_rules"] = baseline.score(w)
    return scores, result


def describe_models(fitted: Fitted, protocol: Protocol) -> dict:
    cfg = {}
    for name, m in fitted.models.items():
        if name in ("existing_iforest_raw", "iforest_deviation"):
            cfg[name] = {"algorithm": "IsolationForest", "n_estimators": m.n_estimators, "max_samples": "min(512, n_train)", "contamination": "auto",
                         "random_state": protocol.seed, "input_features": len(m.used), "dropped_constant_features": m.dropped_constant,
                         "score": "empirical CDF of training scores"}
        elif name == "lof_deviation":
            cfg[name] = {"algorithm": "LocalOutlierFactor(novelty=True)", "n_neighbors": m.n_neighbors, "train_subsample": m.max_train,
                         "random_state": protocol.seed, "input_features": len(m.used), "standardised": True}
        elif name == "robust_z_own":
            cfg[name] = {"algorithm": "mean of the 3 largest positive own-history z-scores", "input_features": len(m.columns)}
        else:
            cfg[name] = {"algorithm": "HistGradientBoostingClassifier", "max_depth": 4, "learning_rate": 0.08, "max_iter": 200,
                         "class_weight": "balanced", "random_state": protocol.seed, "input_features": len(m.columns)}
    cfg["rules_correlation"] = {"algorithm": "behavioural rules with correlation over a decaying window", "decay_per_day": hybrid.DECAY_PER_DAY,
                                "family_weights": {k: v for k, v in hybrid.FAMILY_WEIGHTS.items() if k != "anomaly"}, "rules": [r.code for r in hybrid.RULES if r.family != "anomaly"]}
    cfg["hybrid"] = {"algorithm": "rules + correlation + iforest_deviation anomaly family", "decay_per_day": hybrid.DECAY_PER_DAY,
                     "family_weights": hybrid.FAMILY_WEIGHTS, "anomaly_start": hybrid.ANOMALY_START, "anomaly_full": hybrid.ANOMALY_FULL,
                     "rules": [r.code for r in hybrid.RULES]}
    cfg["baseline_fixed_rules"] = fitted.baseline.describe()
    return cfg


# ---------------------------------------------------------------------------------------------- metrics at three levels
def event_level(w: pd.DataFrame, alert: np.ndarray) -> dict:
    """A window alert flags every event of that window. TP/FN count malicious events, FP/TN count benign events."""
    total = w["n_events"].to_numpy(dtype=float)
    mal = w["n_malicious_events"].to_numpy(dtype=float)
    benign = np.maximum(total - mal - w["n_ambiguous_events"].to_numpy(dtype=float), 0.0)
    tp, fn = float(mal[alert].sum()), float(mal[~alert].sum())
    fp, tn = float(benign[alert].sum()), float(benign[~alert].sum())
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else (0.0 if tp + fp + fn else None)
    return {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn), "precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None, "false_negative_rate": fn / (tp + fn) if tp + fn else None}


def user_level(w: pd.DataFrame, alert: np.ndarray) -> dict:
    """A user is flagged if any evaluated window alerted; a user is an insider if any evaluated window is malicious."""
    frame = pd.DataFrame({"e": w["entity_id"].to_numpy(), "alert": alert, "mal": (w["label"] == 1).to_numpy()}).groupby("e").any()
    y, flagged = frame["mal"].to_numpy(), frame["alert"].to_numpy()
    out = confusion(np.where(y, 1, 0), flagged)
    out["users"] = int(len(frame))
    return out


def evaluate_partition(w: pd.DataFrame, ready: np.ndarray, fitted: Fitted, scores: dict, protocol: Protocol, incidents: pd.DataFrame,
                       inc_status: pd.DataFrame, part: str) -> dict:
    test = _masks(w, ready, part)
    frame = w.loc[test]
    y = frame["label"].to_numpy()
    evaluated_entities = set(frame["entity_id"])
    keep = set()
    if len(inc_status):
        ok = inc_status[(inc_status["split"] == part) & (inc_status["status"] == "evaluated")]
        keep = set(zip(ok["entity_id"], ok["scenario"]))
    events = incidents[[(e, s) in keep for e, s in zip(incidents["entity_id"], incidents["scenario"])]] if len(incidents) else incidents
    out, incident_rows = {}, []
    for name, score in scores.items():
        theta = fitted.thresholds[name]["value"]
        alert_all = fitted.baseline.alerts(w) if name == "baseline_fixed_rules" else score > theta
        alert = alert_all[test]
        entry = {"role": MODEL_ROLES.get(name, name), "threshold": fitted.thresholds[name]["value"], "threshold_kind": fitted.thresholds[name]["kind"],
                 "window_level": _round(confusion(y, alert)), "event_level": _round(event_level(frame, alert)), "user_level": _round(user_level(frame, alert))}
        two = len(set(y)) == 2
        entry["window_level"]["roc_auc"] = round(float(roc_auc_score(y, score[test])), 4) if two else None
        entry["window_level"]["average_precision"] = round(float(average_precision_score(y, score[test])), 4) if two else None
        entry["ci95_user_bootstrap"] = bootstrap_ci(frame, alert, n=protocol.bootstrap_resamples, seed=protocol.seed)
        entry["alerts_per_1000_window_days"] = round(1000 * float(alert.sum()) / max(len(frame), 1), 2)
        entry["recall_at_validation_fpr"] = {}
        for f in protocol.fpr_points:
            if name == "baseline_fixed_rules":
                continue
            c = confusion(y, score[test] > fitted.thresholds[name][f"fpr_{f}"])
            entry["recall_at_validation_fpr"][str(f)] = {"recall": None if c["recall"] is None else round(c["recall"], 4),
                                                         "observed_fpr": None if c["false_positive_rate"] is None else round(c["false_positive_rate"], 5)}
        scen = {}
        for scenario, g in frame[frame["label"] == 1].groupby("scenario"):
            hit = alert_all[g.index.to_numpy()]
            scen[_scenario_key(scenario)] = {"malicious_windows": int(len(g)), "alerted_windows": int(hit.sum()), "window_recall": round(float(hit.mean()), 4)}
        entry["per_scenario_windows"] = scen
        rows = incident_results(events, w, alert_all & test, evaluated_entities) if len(events) else []
        entry["incidents"] = summarise_incidents(rows)
        for r in rows:
            incident_rows.append({"model": name, **r})
        look = {}
        if "benign_scenario" in frame:
            for scenario, g in frame[(frame["label"] == 0) & frame["benign_scenario"].notna()].groupby("benign_scenario"):
                hit = alert_all[g.index.to_numpy()]
                look[str(scenario)] = {"benign_windows": int(len(g)), "false_alerts": int(hit.sum()), "false_positive_rate": round(float(hit.mean()), 4)}
        entry["benign_lookalikes"] = look
        out[name] = entry
    return {"models": out, "incident_rows": incident_rows}


def partition_summary(w: pd.DataFrame, ready: np.ndarray) -> dict:
    out = {}
    for part in ("train", "validation", "test"):
        m = (w["partition"] == part).to_numpy()
        lab = m & ready & w["label"].notna().to_numpy() & ~w["exclude_eval"].to_numpy()
        sub = w.loc[m]
        out[part] = {"users": int(sub["entity_id"].nunique()), "windows": int(m.sum()), "evaluable_windows": int(lab.sum()),
                     "malicious_windows": int((lab & (w["label"] == 1).to_numpy()).sum()), "insiders": int(w.loc[lab & (w["label"] == 1).to_numpy(), "entity_id"].nunique()),
                     "events": int(sub["n_events"].sum()), "malicious_events": int(sub["n_malicious_events"].sum()),
                     "first_day": None if sub.empty else str(sub["day"].min().date()), "last_day": None if sub.empty else str(sub["day"].max().date()),
                     "baseline_warmup_windows_excluded": int((m & ~ready).sum()),
                     "unlabelled_windows_excluded": int((m & ready & w["label"].isna().to_numpy()).sum()),
                     "straddling_incident_windows_excluded": int((m & (w["exclude_eval"] | w["exclude_supervised"]).to_numpy()).sum())}
    return out


LABEL_COLUMNS_TO_BLIND = ("label", "label_note", "scenario", "benign_scenario", "n_malicious_events", "n_ambiguous_events", "first_malicious_ts")


def blind_partition(w: pd.DataFrame, partition: str) -> pd.DataFrame:
    """Copy of the windows with every ground-truth column of one partition blanked, so fitting cannot read those labels."""
    blind = w.copy()
    rows = (blind["partition"] == partition).to_numpy()
    for column in LABEL_COLUMNS_TO_BLIND:
        if column in blind:
            blind.loc[rows, column] = 0.0 if column.startswith("n_") else np.nan
    return blind


def run_track(name: str, windows: pd.DataFrame, splits: pd.DataFrame, attributes, incidents: pd.DataFrame, protocol: Protocol, *,
              partition: str, use_time: bool, dataset_info: dict, log=print) -> tuple[dict, dict]:
    """Returns (result dict for JSON/report, extra tables for CSV)."""
    w = windows.reset_index(drop=True)
    t1, t2 = cutoffs(w, protocol) if use_time else (None, None)
    w, inc_status = assign_partitions(w, splits, incidents, t1, t2)
    assert_partitions_clean(w, t1, t2)
    own_ready = own_baseline_features(w)["baseline_ready"].to_numpy() > 0
    blinded = " (test labels blinded for fitting)" if partition == "test" else " (DEVELOPMENT: validation labels visible)"
    log(f"[{name}] fitting on the train partition, calibrating on validation{blinded} ...")
    w_fit = blind_partition(w, partition) if partition == "test" else w
    fitted = fit_and_calibrate(w_fit, attributes, own_ready, protocol, t1=t1, t2=t2, log=log)
    scores, result = score_models(fitted.models, fitted.baseline, fitted.features, w)
    evaluation = evaluate_partition(w, own_ready, fitted, scores, protocol, incidents, inc_status, partition)
    parts = partition_summary(w, own_ready)
    status_counts = inc_status.groupby(["split", "status"]).size().rename("incidents").reset_index().to_dict("records") if len(inc_status) else []
    state_counts = {k: int(result.states.loc[_masks(w, own_ready, partition), k].sum()) for k in result.states}
    track = {
        "track": name, "evaluated_partition": partition, "development_run": partition != "test", "dataset": dataset_info,
        "split_strategy": {"users": "disjoint train / validation / test (whole users)", "time": "forward-chaining cutoffs" if use_time else "none (users only)",
                           "train_end": None if t1 is None else str(t1.date()), "validation_end": None if t2 is None else str(t2.date()),
                           "train": "train users, days <= train_end" if use_time else "train users, all days",
                           "validation": "validation users, train_end < day <= validation_end" if use_time else "validation users, all days",
                           "test": "test users, day > validation_end" if use_time else "test users, all days"},
        "partitions": parts, "incident_status": status_counts,
        "thresholds": {k: v for k, v in fitted.thresholds.items()}, "model_configuration": describe_models(fitted, protocol),
        "skipped_models": fitted.skipped, "models": evaluation["models"], "hybrid_states_on_evaluated_windows": state_counts,
        "feature_count": len(FEATURE_COLUMNS), "features": FEATURE_COLUMNS,
    }
    return track, {"incident_rows": evaluation["incident_rows"], "incident_status": inc_status}
