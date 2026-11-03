"""Guards that make the evaluation pipeline fail loudly instead of quietly leaking.

* answer-key / label / identity fields can never be model inputs (names AND values);
* partitions are user-disjoint, time-ordered, and never contain synthetic records on the CERT track;
* the CERT track refuses any event file that carries records from another source.
"""
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from ml.cert.leakage import LeakageError, assert_no_leakage
from ml.cert.schema import SOURCE_CERT
from ml.detect.features import FEATURE_COLUMNS

SINGLE_FEATURE_LEAK_AUC = 0.9995        # a lone feature this perfect on train windows is a leak, not a signal
LABEL_LIKE_COLUMNS = {"label", "label_note", "scenario", "benign_scenario", "n_malicious_events", "n_ambiguous_events",
                      "first_malicious_ts", "split", "partition", "exclude_eval", "exclude_supervised", "partition_note",
                      "entity_id", "insider_user", "dataset"}


def assert_model_inputs_clean(model_columns: dict[str, list[str]], frame_columns) -> None:
    """Every model's input columns must be real feature columns and pass the name-based leakage check."""
    allowed = set(FEATURE_COLUMNS)
    for model, columns in model_columns.items():
        assert_no_leakage(columns)
        extra = sorted(set(columns) - allowed)
        if extra:
            raise LeakageError(f"{model}: input column(s) {extra} are not part of the documented feature set")
        missing = sorted(set(columns) - set(frame_columns))
        if missing:
            raise LeakageError(f"{model}: input column(s) {missing} are missing from the feature frame")
    stray = sorted(set(frame_columns) & LABEL_LIKE_COLUMNS)
    if stray:
        raise LeakageError(f"label/answer-key/identity column(s) {stray} found in the feature frame")


def assert_no_single_feature_leak(features: pd.DataFrame, y: np.ndarray, threshold: float = SINGLE_FEATURE_LEAK_AUC) -> None:
    """A single feature that separates train labels (almost) perfectly indicates label leakage."""
    if len(set(y)) < 2 or (y == 1).sum() < 5:
        return
    for column in features.columns:
        values = features[column].to_numpy(dtype=float)
        if np.nanstd(values) == 0:
            continue
        auc = roc_auc_score(y, np.nan_to_num(values))
        if max(auc, 1 - auc) >= threshold:
            raise LeakageError(f"feature '{column}' separates the training labels with AUC {max(auc, 1 - auc):.4f}: suspected label leakage")


def assert_partitions_clean(w: pd.DataFrame, t1=None, t2=None) -> None:
    """User-disjoint partitions, consecutive time ranges, and no synthetic marker anywhere in a CERT track."""
    parts = w[w["partition"].notna()]
    users = parts.groupby("partition")["entity_id"].agg(lambda s: set(s))
    names = list(users.index)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if users[a] & users[b]:
                raise LeakageError(f"users appear in both the '{a}' and '{b}' partitions")
    if t1 is not None:
        if (parts.loc[parts["partition"] == "train", "day"] > t1).any():
            raise LeakageError("a train window lies after the train cutoff")
        val = parts.loc[parts["partition"] == "validation", "day"]
        if len(val) and ((val <= t1).any() or (val > t2).any()):
            raise LeakageError("a validation window lies outside (train cutoff, validation cutoff]")
        if (parts.loc[parts["partition"] == "test", "day"] <= t2).any():
            raise LeakageError("a test window lies before the end of the validation period")


def assert_cert_track_is_cert_only(events: pd.DataFrame) -> None:
    """The held-out CERT track may only contain CERT records."""
    if "is_synthetic" in events and events["is_synthetic"].astype(bool).any():
        raise LeakageError("synthetic records found among CERT events: refusing to build the CERT track")
    if "source" in events and (events["source"].astype(str) != SOURCE_CERT).any():
        raise LeakageError("records from another source found among CERT events: refusing to build the CERT track")


def assert_disjoint_entities(cert_entities: set, synthetic_entities: set) -> None:
    overlap = cert_entities & synthetic_entities
    if overlap:
        raise LeakageError(f"{len(overlap)} entity id(s) occur in both the CERT and the synthetic data")
