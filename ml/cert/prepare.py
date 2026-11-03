"""Repeatable preparation of the CERT Insider Threat Test Dataset (release r4.2) into the project's canonical schema.

    python -m ml.cert.prepare --source data/external/cert/r4.2 --answers data/external/cert/answers --out data/processed/cert_r4.2
    python -m ml.cert.prepare --extract data/external/cert/r4.2.tar.bz2          # safe extraction next to the archive

Outputs (all under --out, none of the original dataset files are modified or overwritten):
    events_<source>.csv.gz   canonical events, NO labels            (training features / dashboard display fields)
    labels.csv               explicit ground truth only             (events absent from it are benign, see labels.py)
    eval_metadata.csv        scenario / insider / incident window   (evaluation only)
    splits.csv               user -> train | validation | test      (+ is_insider, evaluation only)
    identity_map.csv         pseudonymous entity_id -> CERT user id (display / evaluation only)
    entity_attributes.csv    role / department context from LDAP (no names, e-mail addresses, supervisors, psychometrics)
    cert_profile.json        behaviour summary of TRAIN users, benign events only (feeds the synthetic supplement)
    dataset_report.json      counts, rejected rows, duplicates, label coverage, ambiguities, caveats
    manifest.json            release, parameters, file sizes and source checksums when requested
"""
import argparse
import hashlib
import json
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from ml.cert import labels as label_tools
from ml.cert.leakage import assert_disjoint_users
from ml.cert.schema import (
    DEVICE_ACTIVITY,
    EVENT_COLUMNS,
    FIELD_MAP,
    LABEL_AMBIGUOUS,
    LABEL_MALICIOUS,
    LDAP_CONTEXT_COLUMNS,
    LOGON_ACTIVITY,
    RELEASE,
    SOURCE_CERT,
    SOURCES,
    SYNTHETIC_NOTICE,
    TIMESTAMP_FORMAT,
    TIMEZONE_ASSUMPTION,
    DatasetError,
)
from ml.cert.split import split_users
from ml.cert.validate import locate_release, validate_release

CHUNK_ROWS = 500_000
ORG_DOMAIN_FALLBACK = "dtaa.com"
_DOMAIN = r"@([A-Za-z0-9.\-]+)"


def entity_for(user: str) -> str:
    """Stable pseudonym for a CERT user id; the model sees this, never the original identifier."""
    return "E" + hashlib.sha256(f"{SOURCE_CERT}:{user}".encode()).hexdigest()[:12]


# ------------------------------------------------------------------------------------------------ extraction
def extract_archive(archive: str | Path, dest: str | Path | None = None) -> Path:
    """Extract a CERT .tar.bz2 without overwriting anything and without allowing path traversal."""
    archive = Path(archive)
    if not archive.is_file():
        raise DatasetError(f"Archive not found: {archive}")
    dest = Path(dest) if dest else archive.parent
    try:
        with tarfile.open(archive, "r:bz2") as tar:
            tar.extractall(dest, filter="data")      # 'data' rejects absolute paths, '..' and special files
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise DatasetError(f"Could not extract {archive}: {exc}. The download may be incomplete; compare its SHA-256 with "
                           "the official CHECKSUMS-sha256.txt.") from exc
    return dest


# ------------------------------------------------------------------------------------------------ mapping
def _blank(n: int, value="") -> pd.Series:
    return pd.Series([value] * n)


def _common(chunk: pd.DataFrame, entity_map: dict[str, str]) -> pd.DataFrame:
    out = pd.DataFrame({
        "event_id": chunk["id"].to_numpy(), "source": SOURCE_CERT, "timestamp_utc": chunk["_ts"].to_numpy(),
        "entity_id": chunk["user"].map(entity_map).to_numpy(), "host": chunk["pc"].to_numpy(),
    })
    for column in ("event_type", "activity", "auth_result", "destination", "resource"):
        out[column] = ""
    for column in ("bytes", "attachment_count", "recipient_count", "external_recipient_count"):
        out[column] = np.nan
    out["removable_media"] = False
    out["is_synthetic"] = False
    return out


def map_logon(chunk, entity_map, **_):
    activity = chunk["activity"].str.strip().str.lower()
    out = _common(chunk, entity_map)
    out["event_type"] = activity.map(LOGON_ACTIVITY).to_numpy()
    out["activity"] = activity.to_numpy()
    return out


def map_device(chunk, entity_map, **_):
    activity = chunk["activity"].str.strip().str.lower()
    out = _common(chunk, entity_map)
    out["event_type"] = activity.map(DEVICE_ACTIVITY).to_numpy()
    out["activity"] = activity.to_numpy()
    out["removable_media"] = True
    return out


def map_http(chunk, entity_map, **_):
    host = chunk["url"].str.extract(r"^[A-Za-z][A-Za-z0-9+.\-]*://([^/:?#\s]+)", expand=False).str.lower()
    host = host.str.replace(r"^www\.", "", regex=True)
    out = _common(chunk, entity_map)
    out["event_type"] = "web_visit"
    out["destination"] = host.fillna("").to_numpy()
    out["resource"] = host.fillna("").to_numpy()
    return out


def map_file(chunk, entity_map, **_):
    """r4.2 file.csv: 'Each entry represents a file copy to a removable media device' (release readme)."""
    out = _common(chunk, entity_map)
    out["event_type"] = "file_copy_removable"
    out["resource"] = chunk["filename"].fillna("").to_numpy()
    out["removable_media"] = True
    return out


def detect_org_domain(sender_series: pd.Series) -> str:
    domains = sender_series.dropna().astype(str).str.extract(_DOMAIN, expand=False).dropna()
    return domains.mode().iloc[0].lower() if not domains.empty else ORG_DOMAIN_FALLBACK


def map_email(chunk, entity_map, org_domain: str = ORG_DOMAIN_FALLBACK, **_):
    recipients = (chunk["to"].fillna("") + ";" + chunk["cc"].fillna("") + ";" + chunk["bcc"].fillna(""))
    domains = recipients.str.findall(_DOMAIN).map(lambda found: [d.lower() for d in found])
    out = _common(chunk, entity_map)
    out["event_type"] = "email_send"
    out["recipient_count"] = domains.map(len).to_numpy()
    out["external_recipient_count"] = domains.map(lambda ds: sum(d != org_domain for d in ds)).to_numpy()
    out["destination"] = domains.map(lambda ds: ";".join(sorted(set(ds)))).to_numpy()
    out["bytes"] = pd.to_numeric(chunk["size"], errors="coerce").to_numpy()
    out["attachment_count"] = pd.to_numeric(chunk["attachments"], errors="coerce").to_numpy()
    return out


MAPPERS = {"logon": map_logon, "device": map_device, "http": map_http, "email": map_email, "file": map_file}


# ------------------------------------------------------------------------------------------------ pipeline
class _Profile:
    """Behaviour summary of benign events of TRAIN users only (never test users, never labelled events)."""

    def __init__(self):
        self.hours: dict[str, np.ndarray] = {}
        self.day_counts: dict[str, pd.Series] = {}
        self.sizes: list[np.ndarray] = []
        self.rng = np.random.default_rng(0)

    def add(self, kind: str, events: pd.DataFrame) -> None:
        if events.empty:
            return
        stamps = pd.to_datetime(events["timestamp_utc"])
        events = events.assign(_day=stamps.dt.date, _hour=stamps.dt.hour)
        for event_type, group in events.groupby("event_type"):
            hours = np.bincount(group["_hour"].to_numpy(), minlength=24)
            self.hours[event_type] = hours + self.hours.get(event_type, 0)
            per_day = group.groupby(["entity_id", "_day"]).size()
            known = self.day_counts.get(event_type)
            self.day_counts[event_type] = per_day if known is None else known.add(per_day, fill_value=0)
            if event_type == "email_send":
                sizes = pd.to_numeric(group["bytes"], errors="coerce").dropna().to_numpy()
                if len(sizes):
                    self.sizes.append(self.rng.choice(sizes, size=min(len(sizes), 5000), replace=False))

    def summary(self) -> dict:
        out: dict = {"basis": "benign events of train-split users only", "hour_of_day": {}, "per_user_day": {}}
        for kind, hours in self.hours.items():
            total = hours.sum()
            if total:
                out["hour_of_day"][kind] = [round(float(h) / float(total), 5) for h in hours]
        for kind, counts in self.day_counts.items():
            values = counts.to_numpy(dtype=float)
            out["per_user_day"][kind] = {"mean": round(float(values.mean()), 3), "p50": float(np.quantile(values, 0.5)),
                                         "p90": float(np.quantile(values, 0.9)), "p99": float(np.quantile(values, 0.99))}
        if self.sizes:
            joined = np.concatenate(self.sizes)
            out["email_size_bytes"] = {q: round(float(np.quantile(joined, q))) for q in (0.5, 0.9, 0.99)}
        return out


def _read_users(path: Path) -> list[str]:
    users: set[str] = set()
    for chunk in pd.read_csv(path, usecols=["user"], dtype=str, chunksize=CHUNK_ROWS):
        users.update(chunk["user"].dropna().str.strip().unique())
    return sorted(users)


def read_entity_attributes(root: Path, entity_map: dict[str, str]) -> pd.DataFrame | None:
    """Organisational context per pseudonymous entity from the LDAP snapshots (latest snapshot containing the user).

    Only role, business unit, functional unit, department and team are kept. Names, e-mail addresses, supervisors and
    psychometric scores are not copied. NOTE: in r4.2 every scenario-3 insider is a system administrator, so `role`
    is informative about the answer key; do not use it as a feature for a benchmark claim without saying so.
    """
    files = sorted((root / "LDAP").glob("*.csv"))
    if not files:
        return None
    frames = []
    for file in files:
        frame = pd.read_csv(file, dtype=str)
        if "user_id" not in frame.columns:
            raise DatasetError(f"{file.name} has no user_id column; found {list(frame.columns)}")
        frames.append(frame.assign(snapshot=file.stem))
    merged = pd.concat(frames).drop_duplicates("user_id", keep="last")
    merged = merged[merged["user_id"].isin(entity_map)]
    columns = [c for c in LDAP_CONTEXT_COLUMNS if c in merged.columns]
    result = merged[["user_id", *columns, "snapshot"]].copy()
    result.insert(0, "entity_id", result.pop("user_id").map(entity_map))
    return result.sort_values("entity_id").reset_index(drop=True)


def _file_info(path: Path, with_hash: bool) -> dict:
    info = {"bytes": path.stat().st_size}
    if with_hash:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for block in iter(lambda: fh.read(1 << 24), b""):
                digest.update(block)
        info["sha256"] = digest.hexdigest()
    return info


def prepare(source: str | Path, out: str | Path, *, answers: str | Path | None = None, sources: list[str] | None = None,
            sample_users: int | None = None, seed: int = 42, test_fraction: float = 0.30, validation_fraction: float = 0.15,
            hash_sources: bool = False, chunk_rows: int = CHUNK_ROWS) -> dict:
    report = validate_release(source).raise_if_failed()
    root = report.root
    out = Path(out)
    if out.resolve() == root.resolve() or root.resolve() in out.resolve().parents:
        raise DatasetError("--out must not be inside the original dataset directory (originals are never modified)")
    out.mkdir(parents=True, exist_ok=True)
    chosen = [k for k in (sources or list(SOURCES)) if k in report.sources_present]
    unknown = sorted(set(sources or []) - set(SOURCES))
    if unknown:
        raise DatasetError(f"Unknown source(s) {unknown}; choose from {sorted(SOURCES)}")
    if "logon" not in chosen:
        raise DatasetError("logon.csv is required: it defines the population of users")

    answer_events = label_tools.load_answer_events(answers) if answers else None
    incidents = label_tools.load_incidents(answers) if answers else []
    insider_users = {i.user for i in incidents}

    all_users = _read_users(root / SOURCES["logon"].filename)
    selected = set(all_users)
    if sample_users and sample_users < len(all_users):
        rng = np.random.default_rng(seed)
        others = [u for u in all_users if u not in insider_users]
        keep = max(0, sample_users - len(insider_users & set(all_users)))
        selected = (insider_users & set(all_users)) | set(rng.choice(others, size=min(keep, len(others)), replace=False))
    entity_map = {u: entity_for(u) for u in sorted(selected)}
    splits = split_users(list(entity_map.values()), {entity_map[u] for u in insider_users if u in entity_map},
                         test_fraction=test_fraction, validation_fraction=validation_fraction, seed=seed)
    assert_disjoint_users(splits)
    split_of = dict(zip(splits["entity_id"], splits["split"]))
    splits.to_csv(out / "splits.csv", index=False)
    pd.DataFrame({"entity_id": list(entity_map.values()), "user_id": list(entity_map.keys())}).to_csv(out / "identity_map.csv", index=False)
    attributes = read_entity_attributes(root, entity_map)
    if attributes is not None:
        attributes.to_csv(out / "entity_attributes.csv", index=False)

    org_domain = ORG_DOMAIN_FALLBACK
    if "email" in chosen:
        first = next(pd.read_csv(root / SOURCES["email"].filename, usecols=["from"], dtype=str, chunksize=100_000))
        org_domain = detect_org_domain(first["from"])

    label_frame = None
    if answer_events is not None:
        label_frame, eval_meta = label_tools.split_labels_and_metadata(answer_events)
        listed_time = dict(zip(answer_events["event_id"], answer_events["listed_time"]))
    explicit_ids = set(label_frame["event_id"]) if label_frame is not None else set()
    matched: dict[str, str] = {}
    profile = _Profile()
    stats: dict[str, dict] = {}

    for kind in chosen:
        spec, path = SOURCES[kind], root / SOURCES[kind].filename
        target = out / f"events_{kind}.csv.gz"
        if target.exists():
            target.unlink()                      # only our own derived output is replaced, never the originals
        s = {"rows_read": 0, "rows_written": 0, "rejected_missing_fields": 0, "rejected_bad_timestamp": 0,
             "rejected_unknown_activity": 0, "duplicates_dropped": 0, "excluded_by_user_sample": 0}
        seen = np.empty(0, dtype=np.uint64)
        first_write, t_min, t_max = True, None, None
        for chunk in pd.read_csv(path, usecols=list(spec.use), dtype=str, chunksize=chunk_rows):
            s["rows_read"] += len(chunk)
            for column in ("id", "user", "pc"):
                chunk[column] = chunk[column].str.strip()
            missing = chunk[["id", "date", "user"]].isna().any(axis=1) | (chunk["id"] == "") | (chunk["user"] == "")
            s["rejected_missing_fields"] += int(missing.sum())
            chunk = chunk[~missing]
            ts = pd.to_datetime(chunk["date"], format=TIMESTAMP_FORMAT, errors="coerce")
            bad = ts.isna()
            s["rejected_bad_timestamp"] += int(bad.sum())
            chunk = chunk[~bad].assign(_ts=ts[~bad].dt.strftime("%Y-%m-%dT%H:%M:%S+00:00"))
            keep_user = chunk["user"].isin(entity_map)
            s["excluded_by_user_sample"] += int((~keep_user).sum())
            chunk = chunk[keep_user]
            hashes = pd.util.hash_array(chunk["id"].to_numpy(dtype=object))
            repeated = chunk["id"].duplicated().to_numpy() | np.isin(hashes, seen)
            s["duplicates_dropped"] += int(repeated.sum())
            seen = np.union1d(seen, hashes[~repeated])
            chunk = chunk[~repeated]
            if chunk.empty:
                continue
            mapped = MAPPERS[kind](chunk.reset_index(drop=True), entity_map, org_domain=org_domain)
            unknown_activity = mapped["event_type"].isna()
            s["rejected_unknown_activity"] += int(unknown_activity.sum())
            mapped = mapped[~unknown_activity][list(EVENT_COLUMNS)]
            if mapped.empty:
                continue
            hit = mapped["event_id"].isin(explicit_ids)
            for event_id, stamp in zip(mapped.loc[hit, "event_id"], mapped.loc[hit, "timestamp_utc"]):
                matched[event_id] = stamp
            benign_train = (mapped["entity_id"].map(split_of) == "train") & ~hit
            profile.add(kind, mapped[benign_train])
            mapped.to_csv(target, mode="a", header=first_write, index=False, compression="gzip")
            first_write = False
            s["rows_written"] += len(mapped)
            lo, hi = mapped["timestamp_utc"].min(), mapped["timestamp_utc"].max()
            t_min, t_max = min(filter(None, [t_min, lo])), max(filter(None, [t_max, hi]))
        s["first_event"], s["last_event"] = t_min, t_max
        stats[kind] = s

    labels_out, label_report = None, {"answer_key_supplied": answers is not None}
    if label_frame is not None:
        present = label_frame[label_frame["event_id"].isin(matched)]
        present.to_csv(out / "labels.csv", index=False)
        eval_meta[eval_meta["event_id"].isin(matched)].to_csv(out / "eval_metadata.csv", index=False)
        listed = answer_events
        outside = 0
        for row in listed.itertuples():
            if row.event_id in matched and row.label == 1.0:
                stamp = pd.Timestamp(matched[row.event_id]).tz_localize(None)
                lo = pd.to_datetime(row.incident_start, format=TIMESTAMP_FORMAT, errors="coerce")
                hi = pd.to_datetime(row.incident_end, format=TIMESTAMP_FORMAT, errors="coerce")
                if pd.notna(lo) and pd.notna(hi) and not (lo <= stamp <= hi):
                    outside += 1
        by_scenario = {}
        for scenario, group in listed.groupby("scenario"):
            by_scenario[int(scenario)] = {
                "listed_events": int(len(group)), "matched_in_prepared_data": int(group["event_id"].isin(matched).sum()),
                "insiders": int(group["insider_user"].nunique()),
                "ambiguous_other_account": int((group["label_basis"] == LABEL_AMBIGUOUS).sum()),
            }
        label_report.update({
            "incidents_in_key": len(incidents), "insiders": len(insider_users), "events_listed": int(len(listed)),
            "events_matched_in_data": len(matched), "events_unmatched": int(len(listed) - len(matched)),
            "labelled_malicious": int((present["label_basis"] == LABEL_MALICIOUS).sum()),
            "ambiguous_excluded_from_metrics": int((present["label_basis"] == LABEL_AMBIGUOUS).sum()),
            "malicious_events_outside_incident_window": outside,
            "duplicate_listings_in_key": int(listed.attrs.get("duplicate_listings", 0)),
            "by_scenario": by_scenario,
            "rule": ("1 = listed in the answer key and recorded under the insider's own account; ambiguous = listed under "
                     "another account (label missing, excluded from metrics); every other event = benign by absence from "
                     "the key. Insider events outside the listed incident events are NOT labelled malicious."),
        })

    (out / "cert_profile.json").write_text(json.dumps(profile.summary(), indent=2), encoding="utf-8")
    split_counts = splits.groupby("split").agg(users=("entity_id", "size"), insiders=("is_insider", "sum")).to_dict("index")
    caveats = [
        SYNTHETIC_NOTICE, TIMEZONE_ASSUMPTION,
        "Source IP addresses do not exist in this release; 'host' (PC id) is the only location attribute.",
        "Authentication results do not exist (logon.csv has only Logon/Logoff); auth_result is left empty.",
        "File events carry a file name but no size; bytes are only available for e-mail. http/email/file free-text "
        "'content' columns are never read.",
        "Absence from the answer key means benign only by convention; unlisted activity by an insider is unlabelled truth.",
        "r4.2 is a 'dense needles' dataset (release readme): it contains an unrealistically high amount of malicious activity, "
        "so class prevalence and any precision figure are NOT representative of a real organisation.",
        "file.csv records file copies to removable media only (not general file access); logon.csv records screen unlocks as "
        "logons and a few daily logons are intentionally missing (release readme).",
        "LDAP context is kept as role/department only; in r4.2 every scenario-3 insider is a system administrator, so role "
        "carries information about the answer key.",
    ]
    if sample_users:
        caveats.append(f"Only {len(selected)} users were prepared (all insiders kept): class prevalence is NOT representative of the release.")
    if answers is None:
        caveats.append("No answer key supplied: no labels were produced and no supervised metric may be reported.")
    report_doc = {
        "generated_at": datetime.now(timezone.utc).isoformat(), "release": RELEASE, "source": SOURCE_CERT,
        "notice": SYNTHETIC_NOTICE, "users": len(selected), "insiders_in_population": len(insider_users & selected),
        "sources": stats, "splits": split_counts, "labels": label_report, "org_domain": org_domain, "caveats": caveats,
    }
    (out / "dataset_report.json").write_text(json.dumps(report_doc, indent=2, default=str), encoding="utf-8")
    manifest = {
        "release": RELEASE, "source_dir": str(root), "answers_dir": str(answers) if answers else None,
        "parameters": {"seed": seed, "sample_users": sample_users, "sources": chosen, "test_fraction": test_fraction,
                       "validation_fraction": validation_fraction, "chunk_rows": chunk_rows},
        "field_map": FIELD_MAP, "source_files": {k: _file_info(root / SOURCES[k].filename, hash_sources) for k in chosen},
        "reference": {"page": "https://sei.cmu.edu/library/insider-threat-test-dataset/",
                      "doi": "https://doi.org/10.1184/R1/12841247.v1", "license": "CC BY 4.0"},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return report_doc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", help="directory with logon.csv, device.csv, http.csv, email.csv, file.csv")
    parser.add_argument("--answers", help="extracted answers.tar.bz2 directory (insiders.csv and r4.2-N/ folders)")
    parser.add_argument("--out", default="data/processed/cert_r4.2")
    parser.add_argument("--extract", help="extract a downloaded .tar.bz2 archive next to itself, then exit")
    parser.add_argument("--sources", nargs="*", choices=sorted(SOURCES), help="restrict to some event sources")
    parser.add_argument("--sample-users", type=int, help="prepare only N users (all insiders kept) for quick runs")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--hash-sources", action="store_true", help="record SHA-256 of every source file (slow)")
    args = parser.parse_args()
    try:
        if args.extract:
            print(f"extracted into {extract_archive(args.extract)}")
            return 0
        if not args.source:
            parser.error("--source is required")
        result = prepare(args.source, args.out, answers=args.answers, sources=args.sources, sample_users=args.sample_users,
                         seed=args.seed, hash_sources=args.hash_sources)
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({k: result[k] for k in ("users", "sources", "splits", "labels")}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
