"""Benchmark: fit on train users, calibrate on validation users, evaluate on validation (development) or test (once).

    python -m ml.detect.benchmark --dataset cert --processed data/processed/cert_r4.2 --eval-split validation
    python -m ml.detect.benchmark --dataset cert --processed data/processed/cert_r4.2 --eval-split test --final
    python -m ml.detect.benchmark --dataset synthetic --processed data/processed/synthetic_test --eval-split test --final

Model fitting uses benign TRAIN windows only (the supervised reference also uses labelled train windows). The alert
threshold of every model is the benign-validation quantile that gives the target false-positive rate, so test users
never influence a threshold. Evaluating the test split writes a record and refuses to run again unless --force is given.
"""
import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from ml.cert.schema import SYNTHETIC_NOTICE
from ml.detect import hybrid
from ml.detect.dataset import (
    attach_window_labels,
    build_cert_windows,
    incidents_table,
    load_synthetic_windows,
)
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
from ml.detect.models import IsolationForestModel, LocalOutlierFactorModel, RobustZModel, SupervisedReference

TARGET_FPR = 0.005
FPR_POINTS = (0.001, 0.005, 0.01)
LOOKALIKES = ("legit_large_transfer", "approved_odd_hours", "frequent_authorised_access", "routine_removable_media")


# ------------------------------------------------------------------------------------------ metrics
def confusion(y: np.ndarray, alert: np.ndarray) -> dict:
    tp, fp = int(((y == 1) & alert).sum()), int(((y == 0) & alert).sum())
    fn, tn = int(((y == 1) & ~alert).sum()), int(((y == 0) & ~alert).sum())
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else (0.0 if tp + fp + fn else None)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None, "false_negative_rate": fn / (tp + fn) if tp + fn else None}


def threshold_for_fpr(score: np.ndarray, y: np.ndarray, target: float) -> float:
    benign = score[y == 0]
    return float(np.quantile(benign, 1.0 - target)) if len(benign) else float("inf")


def _round(d: dict) -> dict:
    return {k: (round(v, 4) if isinstance(v, float) else v) for k, v in d.items()}


def incident_results(events: pd.DataFrame, windows: pd.DataFrame, alert: np.ndarray, entities: set) -> list[dict]:
    """Per incident: detected?, delay from the first malicious event to the end of the first alerted day, and early-warning share."""
    rows = []
    alerts = windows.assign(_alert=alert)
    alerts = alerts[alerts["_alert"]]
    for (entity, scenario), group in events[events["entity_id"].isin(entities)].groupby(["entity_id", "scenario"]):
        times = group["event_ts"].sort_values().to_numpy()
        first_day, last_day = pd.Timestamp(times[0]).normalize(), pd.Timestamp(times[-1]).normalize()
        mine = alerts[(alerts["entity_id"] == entity) & (alerts["day"] >= first_day) & (alerts["day"] <= last_day)]
        if mine.empty:
            rows.append({"entity_id": entity, "scenario": scenario, "events": len(times), "detected": False})
            continue
        when = mine["day"].min() + pd.Timedelta(days=1)                 # a day window is scored at its end
        after = int((times >= np.datetime64(when)).sum())
        rows.append({"entity_id": entity, "scenario": scenario, "events": len(times), "detected": True,
                     "delay_hours": float((when - pd.Timestamp(times[0])) / pd.Timedelta(hours=1)),
                     "events_after_alert": after, "share_after_alert": after / len(times),
                     "alert_before_last_event": bool(after > 0)})
    return rows


def summarise_incidents(rows: list[dict]) -> dict:
    out = {}
    frame = pd.DataFrame(rows)
    if frame.empty:
        return out
    for scenario, g in list(frame.groupby("scenario")) + [("all", frame)]:
        hit = g[g["detected"]]
        out[_scenario_key(scenario)] = {
            "incidents": int(len(g)), "detected": int(len(hit)), "incident_recall": round(len(hit) / len(g), 4),
            "median_delay_hours": round(float(hit["delay_hours"].median()), 1) if len(hit) else None,
            "median_share_of_events_after_alert": round(float(hit["share_after_alert"].median()), 3) if len(hit) else None,
            "alert_before_last_event": int(hit["alert_before_last_event"].sum()) if len(hit) else 0,
        }
    return out


def bootstrap_ci(frame: pd.DataFrame, alert: np.ndarray, n: int = 300, seed: int = 7) -> dict:
    """User-level bootstrap (resample entities) of precision, recall and false-positive rate."""
    y = frame["label"].to_numpy()
    per = pd.DataFrame({"e": frame["entity_id"].to_numpy(), "tp": (y == 1) & alert, "fp": (y == 0) & alert,
                        "fn": (y == 1) & ~alert, "tn": (y == 0) & ~alert}).groupby("e").sum()
    rng = np.random.default_rng(seed)
    values = per.to_numpy(dtype=float)
    stats = {"precision": [], "recall": [], "false_positive_rate": []}
    for _ in range(n):
        idx = rng.integers(0, len(values), len(values))
        tp, fp, fn, tn = values[idx].sum(axis=0)
        if tp + fp:
            stats["precision"].append(tp / (tp + fp))
        if tp + fn:
            stats["recall"].append(tp / (tp + fn))
        if fp + tn:
            stats["false_positive_rate"].append(fp / (fp + tn))
    return {k: [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)] if v else None for k, v in stats.items()}


# ------------------------------------------------------------------------------------------ pipeline
def prepare_frames(windows: pd.DataFrame, splits: pd.DataFrame, attributes: pd.DataFrame | None):
    """Features for every window; the peer baseline is fitted on benign train windows only."""
    w = windows.merge(splits[["entity_id", "split"]], on="entity_id", how="left").reset_index(drop=True)
    own = own_baseline_features(w)
    ready = own["baseline_ready"].to_numpy() > 0
    benign_train = (w["split"] == "train").to_numpy() & ready & (w["label"] == 0).to_numpy()
    groups = peer_groups(w, attributes)
    peer = PeerBaseline().fit(own[benign_train], groups[benign_train])
    F = build_features(w, peer, attributes)
    return w, F, benign_train, ready


def fit_models(F: pd.DataFrame, w: pd.DataFrame, benign_train: np.ndarray, ready: np.ndarray, seed: int = 42) -> dict:
    train = F[benign_train]
    labelled_train = (w["split"] == "train").to_numpy() & ready & w["label"].notna().to_numpy()
    models = {
        "iforest_raw": IsolationForestModel(RAW_FEATURES, name="iforest_raw", seed=seed).fit(train),
        "iforest_deviation": IsolationForestModel(DEVIATION_FEATURES, name="iforest_deviation", seed=seed).fit(train),
        "lof_deviation": LocalOutlierFactorModel(DEVIATION_FEATURES, seed=seed).fit(train),
        "robust_z_own": RobustZModel([c for c in OWN_FEATURES if c.startswith("z_own_")]).fit(train),
        "supervised_gbm_reference": SupervisedReference(FEATURE_COLUMNS, seed).fit(F[labelled_train], w.loc[labelled_train, "label"].to_numpy().astype(int)),
    }
    return models


def score_all(models: dict, F: pd.DataFrame, w: pd.DataFrame) -> tuple[dict, hybrid.HybridResult]:
    scores = {name: m.score(F) for name, m in models.items()}
    result = hybrid.score_hybrid(F, scores["iforest_deviation"], w["entity_id"], w["day"])
    scores["rules_correlation"] = hybrid.rules_only_risk(F, w["entity_id"], w["day"])
    scores["hybrid"] = result.risk
    return scores, result


def evaluate_models(scores: dict, w: pd.DataFrame, ready: np.ndarray, events: pd.DataFrame, eval_split: str,
                    target_fpr: float = TARGET_FPR) -> dict:
    labelled = ready & w["label"].notna().to_numpy()
    val = labelled & (w["split"] == "validation").to_numpy()
    test = labelled & (w["split"] == eval_split).to_numpy()
    eval_entities = set(w.loc[(w["split"] == eval_split), "entity_id"])
    y_val, y_eval = w.loc[val, "label"].to_numpy(), w.loc[test, "label"].to_numpy()
    frame = w.loc[test]
    report = {}
    for name, score in scores.items():
        theta = threshold_for_fpr(score[val], y_val, target_fpr)
        alert_all = score > theta
        alert = alert_all[test]
        entry = {
            "threshold_calibrated_on_validation": round(theta, 5), "operating_point_fpr_target": target_fpr,
            **_round(confusion(y_eval, alert)),
            "roc_auc": round(float(roc_auc_score(y_eval, score[test])), 4) if len(set(y_eval)) == 2 else None,
            "average_precision": round(float(average_precision_score(y_eval, score[test])), 4) if len(set(y_eval)) == 2 else None,
            "ci95_user_bootstrap": bootstrap_ci(frame, alert),
            "recall_at_validation_fpr": {},
        }
        for fpr in FPR_POINTS:
            t = threshold_for_fpr(score[val], y_val, fpr)
            c = confusion(y_eval, score[test] > t)
            entry["recall_at_validation_fpr"][str(fpr)] = {"recall": round(c["recall"], 4) if c["recall"] is not None else None,
                                                            "observed_fpr": round(c["false_positive_rate"], 5), "threshold": round(t, 5)}
        per_scenario = {}
        for scenario, g in frame[frame["label"] == 1].groupby("scenario"):
            idx = g.index
            hit = alert_all[w.index.get_indexer(idx)]
            per_scenario[_scenario_key(scenario)] = {"malicious_windows": int(len(g)), "alerted_windows": int(hit.sum()), "window_recall": round(float(hit.mean()), 4)}
        entry["per_scenario_windows"] = per_scenario
        rows = incident_results(events, w, alert_all & labelled, eval_entities) if len(events) else []
        entry["incidents"] = summarise_incidents(rows)
        look = {}
        if "benign_scenario" in frame:
            for scenario, g in frame[(frame["label"] == 0) & frame["benign_scenario"].notna()].groupby("benign_scenario"):
                hit = alert_all[w.index.get_indexer(g.index)]
                look[str(scenario)] = {"benign_windows": int(len(g)), "false_alerts": int(hit.sum()), "false_positive_rate": round(float(hit.mean()), 4)}
        entry["benign_lookalikes"] = look
        report[name] = entry
    return report


def _scenario_key(value) -> str:
    try:
        return str(int(float(value)))
    except (TypeError, ValueError):
        return str(value)


def run(dataset: str, processed: Path, eval_split: str, *, final: bool, force: bool, out_dir: Path, seed: int = 42,
        categories: bool = True, log=print) -> dict:
    t0 = time.time()
    tag = "" if categories else "_nocat"
    guard = out_dir / f"final_test_run_{dataset}{tag}.json"
    if eval_split == "test":
        if not final:
            raise SystemExit("Evaluating the test split needs --final (it may be evaluated once).")
        if guard.exists() and not force:
            raise SystemExit(f"The test split was already evaluated ({guard}). Refusing to tune on it; use --force only to reproduce.")
    out_dir.mkdir(parents=True, exist_ok=True)
    cache = processed / "windows_labelled.pkl"
    if cache.exists():
        windows = pd.read_pickle(cache)
    else:
        windows = build_cert_windows(processed, log=log) if dataset == "cert" else None
        if dataset == "cert":
            windows = attach_window_labels(windows, processed, exclude_incident_gaps=True)
        else:
            windows = load_synthetic_windows(processed)
        windows.to_pickle(cache)
    if not categories:
        windows = windows.assign(n_cat_job=0.0, n_cat_exfil=0.0)
    splits = pd.read_csv(processed / "splits.csv")
    attributes = pd.read_csv(processed / "entity_attributes.csv") if (processed / "entity_attributes.csv").exists() else None
    events = incidents_table(processed)
    log(f"{len(windows):,} windows; building features ...")
    w, F, benign_train, ready = prepare_frames(windows, splits, attributes)
    log("fitting models ...")
    models = fit_models(F, w, benign_train, ready, seed)
    scores, result = score_all(models, F, w)
    report = evaluate_models(scores, w, ready, events, eval_split)
    labelled = ready & w["label"].notna().to_numpy()
    counts = {s: {"windows": int(((w["split"] == s) & labelled).sum()), "malicious": int(((w["split"] == s) & labelled & (w["label"] == 1)).sum()),
                  "users": int(w.loc[w["split"] == s, "entity_id"].nunique()),
                  "insiders": int(w.loc[(w["split"] == s) & (w["label"] == 1), "entity_id"].nunique())} for s in ("train", "validation", "test")}
    states = {name: int(result.states.loc[(w["split"] == eval_split).to_numpy() & labelled, name].sum()) for name in result.states}
    excluded = {"baseline_warmup_windows": int((~ready).sum()),
                "ambiguous_or_incident_gap_windows": int((ready & w["label"].isna().to_numpy()).sum()),
                "by_note": w.loc[w["label"].isna() & ready, "label_note"].value_counts().to_dict()}
    payload = {
        "dataset": dataset, "evaluated_split": eval_split, "final_test_run": bool(eval_split == "test"), "domain_categories_enabled": categories,
        "generated_at": pd.Timestamp.utcnow().isoformat(), "seconds": round(time.time() - t0),
        "notice": SYNTHETIC_NOTICE if dataset == "cert" else "Synthetic supplement generated by this project; not CERT data and not real banking data.",
        "unit": "one window = one user on one calendar day; alerts are scored at the end of the day",
        "operating_point": f"alert threshold per model = benign VALIDATION quantile giving false-positive rate {TARGET_FPR}",
        "split_counts": counts, "excluded_windows": excluded,
        "constant_columns_dropped_by_isolation_forest": models["iforest_deviation"].dropped_constant,
        "hybrid_config": {"family_weights": hybrid.FAMILY_WEIGHTS, "decay_per_day": hybrid.DECAY_PER_DAY, "anomaly_start": hybrid.ANOMALY_START,
                          "anomaly_full": hybrid.ANOMALY_FULL, "rules": [r.code for r in hybrid.RULES]},
        "hybrid_state_counts_on_evaluated_windows": states,
        "models": report,
    }
    name = f"{dataset}{tag}_{eval_split}.json"
    (out_dir / name).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    if eval_split == "test":
        config_hash = hashlib.sha256(json.dumps(payload["hybrid_config"], sort_keys=True).encode()).hexdigest()
        guard.write_text(json.dumps({"evaluated_at": payload["generated_at"], "hybrid_config_sha256": config_hash}), encoding="utf-8")
    log(f"wrote {out_dir / name} in {payload['seconds']} s")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", choices=["cert", "synthetic"], required=True)
    parser.add_argument("--processed", required=True)
    parser.add_argument("--eval-split", choices=["validation", "test"], default="validation")
    parser.add_argument("--final", action="store_true", help="required to evaluate the test split (once)")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--no-categories", action="store_true", help="ablation: disable the destination-category enrichment")
    parser.add_argument("--out", default="data/processed/reports")
    args = parser.parse_args()
    run(args.dataset, Path(args.processed), args.eval_split, final=args.final, force=args.force, out_dir=Path(args.out),
        categories=not args.no_categories)
    return 0


if __name__ == "__main__":
    sys.exit(main())
