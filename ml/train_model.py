"""Train the Isolation Forest on NORMAL behaviour only and save it locally.

    python -m ml.train_model            # train + save (ml/artifacts/isolation_forest.joblib)
    python -m ml.train_model --export   # also write the synthetic datasets as CSV for inspection
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from backend import rules
from backend.config import get_settings
from ml.anomaly_detector import volume_guard, volume_reference
from ml.features import FEATURE_NAMES, vectorize
from ml.synthetic_data import HARD_NORMAL_KINDS as HARD, export_csv, generate_dataset, window_features

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"


def _calibrated(raw: np.ndarray, lo: float, hi: float) -> np.ndarray:
    return np.clip((raw - lo) / (hi - lo), 0.0, 1.0)


def train(model_path: str | Path | None = None, *, seed: int = 42, n_employees: int = 60, n_estimators: int = 300,
          export_dir: Path | None = None) -> dict:
    data = generate_dataset(seed=seed, n_employees=n_employees)
    normal_train = [w for w in data.windows if w.label == 0 and w.split == "train"]
    assert normal_train and all(w.label == 0 for w in normal_train)  # never train on attack examples

    X = np.array([vectorize(window_features(data, w)) for w in normal_train])
    model = IsolationForest(n_estimators=n_estimators, max_samples=min(256, len(X)), contamination="auto",
                            random_state=seed).fit(X)
    raw_train = -model.score_samples(X)
    lo = float(np.quantile(raw_train, 0.90))        # upper edge of typical behaviour
    hi = lo + float(rules.scoring("ml_calibration_span"))
    reference = volume_reference([window_features(data, w) for w in normal_train])

    test = [w for w in data.windows if w.split == "test"]
    test_features = [window_features(data, w) for w in test]
    raw_test = -model.score_samples(np.array([vectorize(f) for f in test_features]))
    forest_scores = _calibrated(raw_test, lo, hi)
    guards = np.array([volume_guard(f, reference) for f in test_features])
    scores = np.maximum(forest_scores, guards)
    labels = np.array([w.label for w in test])
    scenarios = np.array([w.scenario for w in test])
    metrics = {
        "roc_auc": round(float(roc_auc_score(labels, scores)), 4),
        "normal_false_positive_rate": round(float((scores[scenarios == "normal"] >= 0.5).mean()), 4),
        "hard_normal_false_positive_rate": round(float((scores[np.isin(scenarios, HARD)] >= 0.5).mean()), 4),
        "hard_normal_false_positive_by_scenario": {s: round(float((scores[scenarios == s] >= 0.5).mean()), 3) for s in HARD},
        "attack_recall": round(float((scores[labels == 1] >= 0.5).mean()), 4),
        "attack_recall_by_scenario": {s: round(float((scores[scenarios == s] >= 0.5).mean()), 3)
                                     for s in sorted(set(scenarios[labels == 1]))},
        "attack_recall_isolation_forest_only": round(float((forest_scores[labels == 1] >= 0.5).mean()), 4),
        "bulk_export_recall_isolation_forest_only": round(float((forest_scores[scenarios == "bulk_export"] >= 0.5).mean()), 3),
        "mean_score_normal": round(float(scores[scenarios == "normal"].mean()), 4),
        "mean_score_attack": round(float(scores[labels == 1].mean()), 4),
        "n_test_normal": int((labels == 0).sum()), "n_test_attack": int((labels == 1).sum()),
    }
    bundle = {
        "model": model, "feature_names": FEATURE_NAMES, "calibration": {"lo": lo, "hi": hi},
        "volume_reference": reference,
        "trained_at": datetime.now(timezone.utc).isoformat(), "n_training_windows": len(normal_train),
        "trained_on": "synthetic normal employee sessions only", "metrics": metrics,
        "sklearn_version": sklearn.__version__, "seed": seed,
    }
    path = Path(model_path or get_settings().ml_model_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    if export_dir:
        export_csv(data, export_dir)
    return {**metrics, "model_path": str(path), "n_training_windows": len(normal_train)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--export", action="store_true", help="write the synthetic datasets as CSV")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(json.dumps(train(seed=args.seed, export_dir=ARTIFACTS if args.export else None), indent=2))
