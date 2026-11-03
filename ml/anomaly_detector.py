"""Isolation Forest anomaly scoring with a heuristic fallback when no trained model is available."""
import logging
import threading
from dataclasses import dataclass
from math import log as _ln, log1p, prod
from pathlib import Path

from backend.config import get_settings
from ml.features import FEATURE_NAMES, vectorize

log = logging.getLogger("insider_threat.ml")


@dataclass
class AnomalyResult:
    score: float          # 0 (typical) .. 1 (highly anomalous), calibrated against normal training data
    raw: float | None     # raw Isolation Forest anomaly score (higher = more anomalous); None in fallback mode
    mode: str             # "isolation_forest" | "fallback"
    volume_guard: float = 0.0   # 0..1 term for volumes beyond anything seen in training (0 in fallback mode)

    def as_dict(self) -> dict:
        return {"score": round(self.score, 4), "raw": None if self.raw is None else round(self.raw, 4), "mode": self.mode,
                "volume_guard": round(self.volume_guard, 4)}


# An Isolation Forest cannot extrapolate: a download 50x larger than anything in training lands in the same outer
# leaf as one 3x larger, so a bare bulk export barely moves its score. The volume guard adds a monotonic term for
# volumes above the largest value seen in normal training sessions (plus a 2x headroom). It reaches 1.0 at
# VOLUME_GUARD_SPAN (in log units) beyond that, i.e. about 10x more records.
VOLUME_FEATURES = ("download_volume", "external_transfer_volume")
VOLUME_GUARD_HEADROOM = _ln(2)     # volumes up to 2x the training maximum are not penalised
VOLUME_GUARD_SPAN = _ln(10)


def volume_reference(rows: list[dict[str, float]]) -> dict[str, float]:
    """Largest value of each volume feature over normal training windows."""
    return {name: max((r[name] for r in rows), default=0.0) for name in VOLUME_FEATURES}


def volume_guard(features: dict[str, float], reference: dict[str, float] | None) -> float:
    if not reference:
        return 0.0
    return max(
        (min(1.0, max(0.0, (features[name] - ref - VOLUME_GUARD_HEADROOM) / VOLUME_GUARD_SPAN))
         for name, ref in reference.items() if name in features),
        default=0.0,
    )


def heuristic_score(f: dict[str, float]) -> float:
    """Fallback anomaly estimate from the same features: bounded, monotonic, no training needed."""
    big = log1p(300)
    parts = [
        min(1.0, f["failed_login_count"] / 6) * 0.6,
        min(1.0, f["restricted_access_attempts"] / 4) * 0.7,
        min(1.0, f["denied_access_count"] / 5) * 0.5,
        f["privilege_escalation"] * 0.6,
        min(1.0, max(0.0, f["download_volume"] - big) / (log1p(5000) - big)) * 0.8,
        min(1.0, f["external_transfer_volume"] / log1p(2000)) * 0.8,
        f["unfamiliar_ip"] * 0.10,
        min(1.0, max(0.0, f["departments_accessed"] - 2) / 3) * 0.4,
    ]
    return 1.0 - prod(1.0 - p for p in parts)


class AnomalyDetector:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or get_settings().ml_model_path)
        self._bundle: dict | None = None
        self.error: str | None = None
        self.load()

    def load(self) -> bool:
        self._bundle, self.error = None, None
        try:
            import joblib

            bundle = joblib.load(self.path)
            if bundle.get("feature_names") != FEATURE_NAMES:
                raise ValueError("model was trained with a different feature set")
            self._bundle = bundle
        except FileNotFoundError:
            self.error = f"model file not found: {self.path}"
        except Exception as exc:  # corrupt file, incompatible scikit-learn version, wrong features
            self.error = f"model could not be loaded: {exc}"
        if self._bundle is None:
            log.warning("Anomaly model unavailable (%s); using fallback scoring", self.error)
        return self._bundle is not None

    @property
    def available(self) -> bool:
        return self._bundle is not None

    def score(self, features: dict[str, float]) -> AnomalyResult:
        if self._bundle is None:
            return AnomalyResult(heuristic_score(features), None, "fallback")
        raw = float(-self._bundle["model"].score_samples([vectorize(features)])[0])
        lo, hi = self._bundle["calibration"]["lo"], self._bundle["calibration"]["hi"]
        forest = min(1.0, max(0.0, (raw - lo) / (hi - lo)))
        guard = volume_guard(features, self._bundle.get("volume_reference"))
        return AnomalyResult(max(forest, guard), raw, "isolation_forest", guard)

    def status(self) -> dict:
        info = {"mode": "isolation_forest" if self.available else "fallback", "model_path": str(self.path),
                "error": self.error, "feature_names": FEATURE_NAMES}
        if self._bundle:
            info.update({k: self._bundle.get(k) for k in ("trained_at", "n_training_windows", "trained_on", "metrics",
                                                          "calibration", "sklearn_version", "volume_reference")})
        return info


_lock = threading.Lock()
_detector: AnomalyDetector | None = None


def get_detector() -> AnomalyDetector:
    global _detector
    with _lock:
        if _detector is None:
            _detector = AnomalyDetector()
        return _detector


def reload_detector() -> AnomalyDetector:
    global _detector
    with _lock:
        _detector = AnomalyDetector()
        return _detector


def ensure_model() -> AnomalyDetector:
    """Load the saved model; train and save one on first start. Falls back to heuristics if that fails."""
    detector = get_detector()
    if not detector.available and get_settings().ml_auto_train:
        try:
            from ml.train_model import train

            log.info("No trained model found; training Isolation Forest on synthetic normal behaviour")
            train()
            detector = reload_detector()
        except Exception:
            log.exception("Automatic model training failed; fallback scoring stays active")
    return detector
