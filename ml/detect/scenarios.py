"""Manually created unit-test scenarios with exact ground truth, evaluated as their own track.

A small, fully controlled world: 36 ordinary users, one malicious bulk export, one malicious gradual collection, one
benign one-off large transfer and one user who routinely sends large transfers. Built from the synthetic generator's
building blocks so it follows the canonical schema, but kept as a separate track (never mixed into the other two).
"""
import random
from dataclasses import dataclass
from datetime import timedelta

import numpy as np
import pandas as pd

from ml.cert.synthetic import DEFAULT_PROFILE, SyntheticConfig, _Builder
from ml.detect.windows import build_windows

N_USERS, DAYS = 40, 75
BULK, GRADUAL, BENIGN_ONCE, POWER = N_USERS - 1, N_USERS - 2, N_USERS - 3, N_USERS - 4
N_TRAIN, N_VALIDATION = 24, 12


def users() -> list[dict]:
    return [dict(user_id=f"SYN-U{i:04d}", entity_id=f"S{i:04d}", host=f"SYNPC-{i}", file_rate=1.0, usb=False, usb_rate=0.0, start_hour=None)
            for i in range(N_USERS)]


@dataclass
class UnitWorld:
    frame: pd.DataFrame
    users: list
    windows: pd.DataFrame
    incidents: pd.DataFrame
    splits: pd.DataFrame
    expectations: dict           # entity_id -> (expected outcome, scenario)
    seed: int


def build_events(seed: int = 5):
    cfg = SyntheticConfig(seed=seed, n_users=N_USERS, days=DAYS, missing_rate=0.0, typo_logon_rate=0.0)
    b = _Builder(cfg, DEFAULT_PROFILE, random.Random(seed))
    people = users()
    for user in people:
        for d in range(DAYS):
            day = b.start + timedelta(days=d)
            if day.weekday() < 5:
                b.normal_day(user, day)
    b.threat("bulk_export", people[BULK], b.start + timedelta(days=60))
    b.threat("gradual_data_collection", people[GRADUAL], b.start + timedelta(days=42))
    b.lookalike("legit_large_transfer", people[BENIGN_ONCE], b.start + timedelta(days=60))
    for d in range(2, 72, 4):                                   # a role that routinely sends large transfers
        b.lookalike("legit_large_transfer", people[POWER], b.start + timedelta(days=d))
    return b, people


def label_windows(windows: pd.DataFrame, frame: pd.DataFrame, labels: pd.DataFrame, meta: pd.DataFrame):
    """Window labels from the generator's exact ground truth; returns labelled windows and the incident event table."""
    ts = pd.to_datetime(frame["timestamp_utc"].str.slice(0, 19), format="%Y-%m-%dT%H:%M:%S")
    ev = frame[["event_id", "entity_id"]].assign(ts=ts, day=ts.dt.normalize())
    mal = ev.merge(labels[["event_id"]], on="event_id").merge(meta[["event_id", "scenario"]], on="event_id")
    keys = ["entity_id", "day"]
    per = mal.groupby(keys).agg(n_malicious_events=("event_id", "size"), first_malicious_ts=("ts", "min"), scenario=("scenario", "first")).reset_index()
    out = windows.merge(per, on=keys, how="left")
    out["n_malicious_events"] = out["n_malicious_events"].fillna(0)
    out["n_ambiguous_events"] = 0.0
    out["label"] = np.where(out["n_malicious_events"] > 0, 1.0, 0.0)
    out["label_note"] = np.where(out["label"] == 1, "malicious_events_listed", "benign")
    benign = meta[~meta["event_id"].isin(labels["event_id"])]
    look = ev.merge(benign[["event_id", "scenario"]], on="event_id").groupby(keys)["scenario"].first().rename("benign_scenario").reset_index()
    out = out.merge(look, on=keys, how="left")
    incidents = mal.rename(columns={"ts": "event_ts"})[["event_id", "entity_id", "scenario", "event_ts"]]
    return out, incidents


def build_unit_world(seed: int = 5) -> UnitWorld:
    b, people = build_events(seed)
    frame = pd.DataFrame(b.rows)
    ids = [u["entity_id"] for u in people]
    normals = set(ids[: N_TRAIN + N_VALIDATION])
    windows = build_windows(frame, train_entities=set(ids[:N_TRAIN]))
    labels = pd.DataFrame(b.labels, columns=["event_id", "label", "label_basis"])
    meta = pd.DataFrame(b.meta, columns=["event_id", "scenario", "insider_user", "incident_file", "incident_start", "incident_end"])
    windows, incidents = label_windows(windows, frame, labels, meta)
    split = ["train"] * N_TRAIN + ["validation"] * N_VALIDATION + ["test"] * (N_USERS - N_TRAIN - N_VALIDATION)
    splits = pd.DataFrame({"entity_id": ids, "split": split})
    expect = {people[BULK]["entity_id"]: ("malicious", "bulk_export"), people[GRADUAL]["entity_id"]: ("malicious", "gradual_data_collection"),
              people[BENIGN_ONCE]["entity_id"]: ("benign", "legit_large_transfer"), people[POWER]["entity_id"]: ("benign", "routine_large_transfers")}
    assert normals.isdisjoint(expect)
    return UnitWorld(frame, people, windows, incidents, splits, expect, seed)
