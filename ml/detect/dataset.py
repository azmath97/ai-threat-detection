"""Load prepared datasets (ml.cert.prepare / ml.cert.synthetic output), build windows and attach window-level labels.

Labels are attached *after* the windows are built and live in separate columns (`label`, `label_note`, `scenario`,
`n_malicious_events`, ...). They are never read by the feature pipeline (see ml.detect.features.FEATURE_COLUMNS).
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from ml.cert.schema import DatasetError
from ml.detect.windows import (
    DomainContext,
    aggregate_other,
    aggregate_web,
    build_windows,
    combine_windows,
    prepare_frame,
)

WEB_COLUMNS = ["event_id", "timestamp_utc", "entity_id", "destination"]
OTHER_COLUMNS = ["event_id", "timestamp_utc", "entity_id", "host", "event_type", "activity", "auth_result", "destination", "resource",
                 "bytes", "attachment_count", "recipient_count", "external_recipient_count", "removable_media"]


def iter_complete_days(path: Path, columns: list[str], chunk_rows: int = 1_000_000):
    """Yield prepared blocks that contain only complete days (events are time ordered; verified by prepare)."""
    carry = None
    for chunk in pd.read_csv(path, usecols=columns, chunksize=chunk_rows):
        chunk["_d"] = chunk["timestamp_utc"].str.slice(0, 10)
        frame = chunk if carry is None else pd.concat([carry, chunk], ignore_index=True)
        last = frame["_d"].iloc[-1]
        carry = frame[frame["_d"] == last]
        done = frame[frame["_d"] != last].drop(columns="_d")
        if len(done):
            done["event_type"] = "web_visit"
            yield prepare_frame(done)
    if carry is not None and len(carry):
        carry = carry.drop(columns="_d")
        carry["event_type"] = "web_visit"
        yield prepare_frame(carry)


def load_split_entities(processed: Path, split: str) -> set:
    splits = pd.read_csv(processed / "splits.csv")
    return set(splits.loc[splits["split"] == split, "entity_id"])


def build_cert_windows(processed: str | Path, *, chunk_rows: int = 1_000_000, log=print) -> pd.DataFrame:
    """Streaming window build for the prepared CERT release (two passes over http, everything else in memory)."""
    processed = Path(processed)
    http = processed / "events_http.csv.gz"
    train = load_split_entities(processed, "train")
    ctx_path = processed / "domain_context.pkl"
    ctx = DomainContext(train)
    if http.exists() and ctx_path.exists():
        ctx = pd.read_pickle(ctx_path)
    elif http.exists():
        log("pass 1/2: destination statistics from http ...")
        for block in iter_complete_days(http, WEB_COLUMNS, chunk_rows):
            ctx.update(block)
        ctx.finalize()
        pd.to_pickle(ctx, ctx_path)
    if http.exists():
        log("pass 2/2: web windows ...")
        parts = [aggregate_web(block, ctx) for block in iter_complete_days(http, WEB_COLUMNS, chunk_rows)]
        web = pd.concat([p for p in parts if len(p)], ignore_index=True) if parts else pd.DataFrame()
    else:
        web = pd.DataFrame()
    frames = []
    for kind in ("logon", "device", "file", "email"):
        path = processed / f"events_{kind}.csv.gz"
        if path.exists():
            frames.append(pd.read_csv(path, usecols=OTHER_COLUMNS))
    log("non-web windows ...")
    other = aggregate_other(prepare_frame(pd.concat(frames, ignore_index=True))) if frames else pd.DataFrame()
    return combine_windows(web, other)


def labelled_events(processed: Path, event_ids: set, *, files: list[str] | None = None) -> pd.DataFrame:
    """Entity and timestamp of every event that has a ground-truth entry (scans the event files by id only)."""
    names = files or sorted(p.name for p in processed.glob("events_*.csv.gz"))
    found = []
    for name in names:
        for chunk in pd.read_csv(processed / name, usecols=["event_id", "entity_id", "timestamp_utc", "event_type"], chunksize=2_000_000):
            hit = chunk[chunk["event_id"].isin(event_ids)]
            if len(hit):
                found.append(hit)
    if not found:
        raise DatasetError(f"None of the {len(event_ids)} labelled event ids were found in {processed}")
    out = pd.concat(found, ignore_index=True)
    out["ts"] = pd.to_datetime(out["timestamp_utc"].str.slice(0, 19), format="%Y-%m-%dT%H:%M:%S")
    return out


def attach_window_labels(windows: pd.DataFrame, processed: str | Path, *, exclude_incident_gaps: bool) -> pd.DataFrame:
    """Add `label` (1 malicious, 0 benign, NaN excluded), `label_note`, `scenario`, event counts and first malicious time."""
    processed = Path(processed)
    labels = pd.read_csv(processed / "labels.csv")
    meta = pd.read_csv(processed / "eval_metadata.csv")
    events = labelled_events(processed, set(labels["event_id"])).merge(labels, on="event_id", how="left").merge(
        meta[["event_id", "scenario", "insider_user", "incident_start", "incident_end"]], on="event_id", how="left")
    events["day"] = events["ts"].dt.normalize()
    events["is_malicious"] = events["label"] == 1
    events["is_ambiguous"] = events["label"].isna()
    keys = ["entity_id", "day"]
    per = events.groupby(keys).agg(n_malicious_events=("is_malicious", "sum"), n_ambiguous_events=("is_ambiguous", "sum"))
    mal = events[events["is_malicious"]]
    per["first_malicious_ts"] = mal.groupby(keys)["ts"].min()
    per["scenario"] = mal.groupby(keys)["scenario"].agg(lambda s: s.mode().iloc[0])
    out = windows.merge(per.reset_index(), on=keys, how="left")
    out["n_malicious_events"] = out["n_malicious_events"].fillna(0)
    out["n_ambiguous_events"] = out["n_ambiguous_events"].fillna(0)
    out["label"] = np.where(out["n_malicious_events"] > 0, 1.0, 0.0)
    out["label_note"] = np.where(out["label"] == 1, "malicious_events_listed", "benign_by_absence")
    ambiguous = (out["label"] == 0) & (out["n_ambiguous_events"] > 0)
    out.loc[ambiguous, ["label", "label_note"]] = [np.nan, "ambiguous_other_account_events"]
    benign_ids = set(meta["event_id"]) - set(labels["event_id"])
    if benign_ids:        # scenario metadata on events that are benign by construction (synthetic benign lookalikes)
        look = labelled_events(processed, benign_ids).merge(meta[["event_id", "scenario"]], on="event_id")
        look["day"] = look["ts"].dt.normalize()
        named = look.groupby(keys)["scenario"].agg(lambda s: s.mode().iloc[0]).rename("benign_scenario").reset_index()
        out = out.merge(named, on=keys, how="left")
    if exclude_incident_gaps:
        # An insider's unlisted days inside their incident window are unlabelled truth, not known-benign.
        spans = events.dropna(subset=["incident_start"]).copy()
        spans["s"] = pd.to_datetime(spans["incident_start"], format="%m/%d/%Y %H:%M:%S").dt.normalize()
        spans["e"] = pd.to_datetime(spans["incident_end"], format="%m/%d/%Y %H:%M:%S").dt.normalize()
        span = spans.groupby("entity_id").agg(s=("s", "min"), e=("e", "max"))
        joined = out.join(span, on="entity_id")
        inside = joined["s"].notna() & (joined["day"] >= joined["s"]) & (joined["day"] <= joined["e"]) & (out["label"] == 0)
        out.loc[inside, ["label", "label_note"]] = [np.nan, "inside_incident_window_unlisted"]
    return out


def incidents_table(processed: str | Path) -> pd.DataFrame:
    """One row per (entity, scenario) incident with its listed malicious events and their times (for delay metrics)."""
    processed = Path(processed)
    labels = pd.read_csv(processed / "labels.csv")
    meta = pd.read_csv(processed / "eval_metadata.csv")
    events = labelled_events(processed, set(labels["event_id"])).merge(labels, on="event_id").merge(
        meta[["event_id", "scenario", "insider_user"]], on="event_id")
    events = events[events["label"] == 1]
    return events[["event_id", "entity_id", "scenario", "ts"]].rename(columns={"ts": "event_ts"})


def load_synthetic_windows(processed: str | Path) -> pd.DataFrame:
    processed = Path(processed)
    events = pd.read_csv(processed / "events_synthetic_test.csv.gz")
    train = set(pd.read_csv(processed / "splits.csv").query("split == 'train'")["entity_id"]) if (processed / "splits.csv").exists() else None
    windows = build_windows(events, train_entities=train)
    return attach_window_labels(windows, processed, exclude_incident_gaps=False)


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
