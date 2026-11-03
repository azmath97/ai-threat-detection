"""Evaluation protocol: time-aware partitions, scenario-leak control, provenance (versions, seed, commit, hashes).

Partitions (a window = one user on one day):
    train       train-split users,      days <= train_end
    validation  validation-split users, train_end < days <= validation_end   (thresholds are calibrated here, benign windows only)
    test        test-split users,       days > validation_end

Users are disjoint across partitions and the time ranges are consecutive, so no attack scenario (one user's incident) can
appear on both sides. Incidents that straddle a cutoff are not silently dropped or half-used: a straddling TRAIN incident is
excluded from supervised training, a straddling TEST incident is excluded from evaluation (its windows after the cutoff
have no known start inside the test period), and every such incident is listed in the report.
"""
import hashlib
import json
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd


@dataclass
class Protocol:
    name: str = "forward-chaining-v2"
    seed: int = 42
    target_fpr: float = 0.005
    fpr_points: tuple = (0.001, 0.005, 0.01)
    train_end_fraction: float | None = 0.45         # of the window date range; None disables the time cut (users only)
    validation_end_fraction: float | None = 0.55
    bootstrap_resamples: int = 300
    min_supervised_positives: int = 20
    notes: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def cutoffs(windows: pd.DataFrame, protocol: Protocol):
    if protocol.train_end_fraction is None:
        return None, None
    start, end = windows["day"].min(), windows["day"].max()
    span = end - start
    return (start + span * protocol.train_end_fraction).normalize(), (start + span * protocol.validation_end_fraction).normalize()


def assign_partitions(w: pd.DataFrame, splits: pd.DataFrame, incidents: pd.DataFrame, t1, t2) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Add `split`, `partition` and `exclude_supervised` / `exclude_eval` to the windows; return the incident status table."""
    w = w.drop(columns=[c for c in ("split", "partition", "exclude_eval", "exclude_supervised", "partition_note") if c in w]).merge(
        splits[["entity_id", "split"]], on="entity_id", how="left")
    day = w["day"]
    if t1 is None:
        partition = w["split"].where(w["split"].isin(["train", "validation", "test"]))
    else:
        partition = pd.Series(np.select(
            [(w["split"] == "train") & (day <= t1), (w["split"] == "validation") & (day > t1) & (day <= t2), (w["split"] == "test") & (day > t2)],
            ["train", "validation", "test"], default=None), index=w.index)
    w["partition"] = partition
    w["exclude_supervised"] = False
    w["exclude_eval"] = False
    w["partition_note"] = ""
    rows = []
    if len(incidents):
        span = incidents.groupby(["entity_id", "scenario"])["event_ts"].agg(["min", "max", "size"]).reset_index()
        split_of = dict(zip(splits["entity_id"], splits["split"]))
        for r in span.itertuples():
            split, d0, d1 = split_of.get(r.entity_id), pd.Timestamp(r.min).normalize(), pd.Timestamp(r.max).normalize()
            status = "evaluated" if split == "test" else "not_in_test"
            cut = {"train": t1, "validation": t2, "test": t2}.get(split)
            if t1 is not None and split in ("train", "test") and cut is not None:
                mine = (w["entity_id"] == r.entity_id) & (w["day"] >= d0) & (w["day"] <= d1)
                if split == "test" and d1 <= t2:
                    status = "before_test_period"
                elif split == "test" and d0 <= t2 < d1:
                    status = "straddles_test_cutoff"
                    w.loc[mine, ["exclude_eval", "partition_note"]] = [True, "straddling_incident"]
                elif split == "train" and d0 <= t1 < d1:
                    status = "straddles_train_cutoff"
                    w.loc[mine, ["exclude_supervised", "partition_note"]] = [True, "straddling_incident"]
            rows.append({"entity_id": r.entity_id, "scenario": r.scenario, "split": split, "first_event": str(r.min), "last_event": str(r.max),
                         "events": int(r.size), "status": status})
    return w, pd.DataFrame(rows)


def software_versions() -> dict:
    import sklearn

    versions = {"python": sys.version.split()[0], "platform": platform.platform(), "numpy": np.__version__, "pandas": pd.__version__,
                "scikit-learn": sklearn.__version__}
    try:
        import scipy

        versions["scipy"] = scipy.__version__
    except ImportError:
        pass
    return versions


def git_state(root: Path) -> dict:
    def run(*args):
        try:
            return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=20).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    return {"commit": run("rev-parse", "HEAD") or "unknown", "uncommitted_changes": bool(run("status", "--porcelain"))}


def file_digest(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 22), b""):
            h.update(block)
    return h.hexdigest()


def config_hash(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
