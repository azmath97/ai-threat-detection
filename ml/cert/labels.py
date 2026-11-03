"""Ground-truth labels from the official answer key (answers.tar.bz2).

Rules (also in docs/cert-dataset.md):
* The key lists, per incident, the exact events (type, CERT event id, time, account) that make up the malicious activity.
* An event is labelled malicious (1) only if its id is listed AND it was performed by the insider's own account.
* A listed event recorded under another account (for example a colleague's account used during incident 3, or a
  reply) is ambiguous: label is missing (NaN) and it is excluded from supervised metrics.
* Everything else is "no answer-key entry" and is treated as benign (0). That is the best the source permits: it
  cannot prove that an unlisted event by an insider was innocent, which is reported as a limitation.
* Labels are stored apart from the events and never feed model inputs.
"""
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from ml.cert.schema import (
    EVAL_METADATA_COLUMNS,
    LABEL_AMBIGUOUS,
    LABEL_BENIGN,
    LABEL_MALICIOUS,
    RELEASE,
    TIMESTAMP_FORMAT,
    DatasetError,
)
from ml.cert.validate import validate_answers


@dataclass(frozen=True)
class Incident:
    scenario: int
    user: str
    file: str
    start: str
    end: str


def load_incidents(answers_dir: str | Path, release: str = RELEASE) -> list[Incident]:
    directory = validate_answers(answers_dir)
    frame = pd.read_csv(directory / "insiders.csv", dtype=str)
    rows = frame[frame["dataset"] == release.lstrip("r")]
    return [Incident(int(r.scenario), r.user.strip(), r.details.strip(), r.start, r.end) for r in rows.itertuples()]


def _incident_path(directory: Path, incident: Incident, release: str) -> Path:
    for candidate in (directory / f"{release}-{incident.scenario}" / incident.file, directory / incident.file):
        if candidate.exists():
            return candidate
    raise DatasetError(f"Answer-key observables file for incident {incident.file} (user {incident.user}) not found under "
                       f"{directory / f'{release}-{incident.scenario}'}")


def load_answer_events(answers_dir: str | Path, release: str = RELEASE) -> pd.DataFrame:
    """One row per answer-key event: ids, listed account, incident metadata and the resulting label."""
    directory = validate_answers(answers_dir)
    records, conflicts = [], 0
    seen: set[str] = set()
    for incident in load_incidents(directory, release):
        path = _incident_path(directory, incident, release)
        with path.open(encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, 1):
                line = line.rstrip("\r\n")
                if not line:
                    continue
                parts = line.split(",", 5)       # rows are variable length; only the first five fields are used
                if len(parts) < 5 or not parts[1].startswith("{"):
                    raise DatasetError(f"{path.name} line {number} is malformed (expected type,id,date,user,pc,...): {line[:80]!r}")
                kind, event_id, date, user, _pc = (p.strip() for p in parts[:5])
                if event_id in seen:
                    conflicts += 1                # same event listed twice: keep the first, count the rest
                    continue
                seen.add(event_id)
                own = user == incident.user
                records.append({
                    "event_id": event_id, "listed_type": kind, "listed_user": user, "listed_time": date,
                    "scenario": incident.scenario, "insider_user": incident.user, "incident_file": incident.file,
                    "incident_start": incident.start, "incident_end": incident.end,
                    "label": 1.0 if own else np.nan, "label_basis": LABEL_MALICIOUS if own else LABEL_AMBIGUOUS,
                })
    frame = pd.DataFrame.from_records(records)
    frame.attrs["duplicate_listings"] = conflicts
    if frame.empty:
        raise DatasetError(f"The answer key under {directory} lists no events for release {release}")
    return frame


def split_labels_and_metadata(answers: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Separate ground truth (labels) from evaluation metadata so neither can leak into features."""
    labels = answers[["event_id", "label", "label_basis"]].copy()
    metadata = answers[list(EVAL_METADATA_COLUMNS)].copy()
    return labels, metadata


def apply_labels(event_ids: pd.Series, labels: pd.DataFrame) -> pd.DataFrame:
    """Label for each event id: 1 malicious, NaN ambiguous, 0 benign (no answer-key entry)."""
    lookup = labels.set_index("event_id")
    joined = lookup.reindex(event_ids.to_numpy())
    out = pd.DataFrame({"event_id": event_ids.to_numpy(), "label": joined["label"].to_numpy(),
                        "label_basis": joined["label_basis"].to_numpy()})
    unlisted = joined["label_basis"].isna().to_numpy()
    out.loc[unlisted, "label"] = 0.0
    out.loc[unlisted, "label_basis"] = LABEL_BENIGN
    return out


def parse_time(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, format=TIMESTAMP_FORMAT, errors="coerce")
