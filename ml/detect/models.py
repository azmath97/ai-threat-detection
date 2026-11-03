"""Scoring models over window features. All unsupervised models are fitted on benign train windows only.

Scores are normalised to 0..1 by the empirical CDF of the *training* scores, so "0.99" means "higher than 99 % of the
benign windows the model was fitted on", which is comparable across models and independent of the model's raw scale.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler


class _Ecdf:
    def __init__(self, values: np.ndarray):
        self.sorted = np.sort(np.asarray(values, dtype=float))

    def __call__(self, values: np.ndarray) -> np.ndarray:
        return np.searchsorted(self.sorted, values, side="right") / max(len(self.sorted), 1)


class IsolationForestModel:
    """Isolation Forest on the chosen columns (zero-variance training columns are dropped and recorded)."""

    def __init__(self, columns: list[str], *, name: str, n_estimators: int = 200, seed: int = 42):
        self.columns, self.name, self.n_estimators, self.seed = columns, name, n_estimators, seed

    def fit(self, X: pd.DataFrame) -> "IsolationForestModel":
        self.used = [c for c in self.columns if X[c].std() > 0]
        self.dropped_constant = [c for c in self.columns if c not in self.used]
        self.model = IsolationForest(n_estimators=self.n_estimators, max_samples=min(512, len(X)), contamination="auto",
                                     random_state=self.seed, n_jobs=-1).fit(X[self.used].to_numpy(dtype=float))
        self.ecdf = _Ecdf(-self.model.score_samples(X[self.used].to_numpy(dtype=float)))
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        return self.ecdf(-self.model.score_samples(X[self.used].to_numpy(dtype=float)))


class LocalOutlierFactorModel:
    """LOF in novelty mode on a standardised random subsample of the training windows."""

    def __init__(self, columns: list[str], *, name: str = "lof_deviation", n_neighbors: int = 35, max_train: int = 30000, seed: int = 42):
        self.columns, self.name, self.n_neighbors, self.max_train, self.seed = columns, name, n_neighbors, max_train, seed

    def fit(self, X: pd.DataFrame) -> "LocalOutlierFactorModel":
        self.used = [c for c in self.columns if X[c].std() > 0]
        sample = X.sample(min(self.max_train, len(X)), random_state=self.seed)
        self.scaler = StandardScaler().fit(sample[self.used].to_numpy(dtype=float))
        self.model = LocalOutlierFactor(n_neighbors=self.n_neighbors, novelty=True, n_jobs=-1).fit(
            self.scaler.transform(sample[self.used].to_numpy(dtype=float)))
        self.ecdf = _Ecdf(-self.model.score_samples(self.scaler.transform(sample[self.used].to_numpy(dtype=float))))
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        return self.ecdf(-self.model.score_samples(self.scaler.transform(X[self.used].to_numpy(dtype=float))))


class RobustZModel:
    """Non-ML reference: mean of the three largest positive own-history z-scores of the day."""

    name = "robust_z_own"

    def __init__(self, columns: list[str]):
        self.columns = columns

    def _raw(self, X: pd.DataFrame) -> np.ndarray:
        z = np.sort(np.clip(X[self.columns].to_numpy(dtype=float), 0, None), axis=1)[:, -3:]
        return z.mean(axis=1)

    def fit(self, X: pd.DataFrame) -> "RobustZModel":
        self.ecdf = _Ecdf(self._raw(X))
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        return self.ecdf(self._raw(X))


class SupervisedReference:
    """Gradient boosting trained on LABELLED train windows. A reference ceiling only: real deployments rarely have labels."""

    name = "supervised_gbm_reference"

    def __init__(self, columns: list[str], seed: int = 42):
        self.columns, self.seed = columns, seed

    def fit(self, X: pd.DataFrame, y: np.ndarray) -> "SupervisedReference":
        self.model = HistGradientBoostingClassifier(max_depth=4, learning_rate=0.08, max_iter=200, class_weight="balanced",
                                                    random_state=self.seed).fit(X[self.columns].to_numpy(dtype=float), y)
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        return self.model.predict_proba(X[self.columns].to_numpy(dtype=float))[:, 1]
