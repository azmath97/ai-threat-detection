"""One command that runs the whole evaluation and writes a machine-readable and a human-readable report.

    python -m ml.detect.run_evaluation --cert-processed data/processed/cert_r4.2 --out reports/evaluation --partition test --final

Writes to --out: results.json (everything), manifest.json (provenance), report.md, and flat CSV tables per track
(`<track>_models.csv`, `_scenarios.csv`, `_thresholds.csv`, `_incidents.csv`, `_incident_status.csv`).

Tracks (never combined): CERT held-out users, project-generated synthetic scenarios (fresh seed), unit-test scenarios.
Evaluating the test partition needs --final and is allowed once per output directory.
"""
import argparse
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

import pandas as pd

from ml.cert import synthetic
from ml.cert.schema import SOURCE_CERT, SYNTHETIC_NOTICE
from ml.detect import hybrid, scenarios
from ml.detect.dataset import attach_window_labels, build_cert_windows, incidents_table, load_synthetic_windows
from ml.detect.evaluate import run_track
from ml.detect.features import FEATURE_COLUMNS
from ml.detect.protocol import Protocol, config_hash, file_digest, git_state, software_versions
from ml.detect.report import flatten, render

ROOT = Path(__file__).resolve().parents[2]
LIMITATIONS = [
    "The CERT Insider Threat Test Dataset is synthetic (generated background users plus synthetic malicious actors). It is not real banking "
    "data, and its scenarios (removable-media theft, job-site browsing, an administrator keylogger) may not represent real organisations.",
    "CERT r4.2 is a \"dense needles\" release: malicious activity is far more common than in reality, so precision and F1 are inflated relative to a real "
    "deployment and must not be extrapolated.",
    "Labels may be incomplete. The answer key lists the events the red team injected; an insider's unlisted activity is treated as benign by "
    "convention (or excluded when inside the incident window), and events listed under another account are excluded as ambiguous.",
    "There are few incidents in the held-out CERT partition, so intervals are wide and per-scenario figures (especially scenario 3) are indicative only.",
    "Validation windows used for calibration cover a short period, so thresholds are noisy: the false-positive rate observed on the test "
    "partition differs from the target, and models should be compared in the fixed-FPR recall table as well as at the operating point.",
    "Detection delay is measured on day windows scored at day end; it cannot show earlier-than-a-day detection, and single-day incidents "
    "cannot be alerted before they end. Early warning is only demonstrable for incidents that span several days.",
    "The synthetic and unit-test tracks were created by this project, so their scenarios reflect its own assumptions and the destination-category "
    "lists were written after reading the CERT scenario descriptions (results with them are optimistic for those scenarios).",
    "The 'existing detector' is the original approach (Isolation Forest on raw per-day volumes). The live application engine scores individual "
    "events with IP-based features that do not exist in CERT, so it cannot be run on this data.",
    "This project has not been validated for live banking use. It does not protect a real network; containment is a simulation of application state.",
]


def hybrid_config() -> dict:
    return {"family_weights": hybrid.FAMILY_WEIGHTS, "decay_per_day": hybrid.DECAY_PER_DAY, "anomaly_start": hybrid.ANOMALY_START,
            "anomaly_full": hybrid.ANOMALY_FULL, "rules": [r.code for r in hybrid.RULES]}


def frozen_config_check(reports_dir: Path) -> str:
    record = reports_dir / "final_test_run_cert.json"
    if not record.exists():
        return "no earlier test-run record found"
    frozen = json.loads(record.read_text(encoding="utf-8")).get("hybrid_config_sha256")
    now = config_hash(hybrid_config())
    return "yes" if frozen == now else f"NO: configuration changed since the first CERT test evaluation ({frozen} -> {now})"


def verify_cert_sources(processed: Path) -> dict:
    counts: dict = {}
    synthetic_rows = 0
    for path in sorted(processed.glob("events_*.csv.gz")):
        for chunk in pd.read_csv(path, usecols=["source", "is_synthetic"], chunksize=2_000_000):
            for key, n in chunk["source"].value_counts().items():
                counts[key] = counts.get(key, 0) + int(n)
            synthetic_rows += int(chunk["is_synthetic"].astype(bool).sum())
    if set(counts) - {SOURCE_CERT} or synthetic_rows:
        raise SystemExit(f"The CERT event files contain records that are not CERT: sources {counts}, synthetic rows {synthetic_rows}")
    return {"event_sources_found": counts, "synthetic_rows": synthetic_rows}


def cert_dataset_info(processed: Path, windows: pd.DataFrame, splits: pd.DataFrame, categories: bool) -> dict:
    report = json.loads((processed / "dataset_report.json").read_text(encoding="utf-8"))
    manifest = json.loads((processed / "manifest.json").read_text(encoding="utf-8"))
    labels = pd.read_csv(processed / "labels.csv")
    return {
        "dataset": "CERT Insider Threat Test Dataset (Carnegie Mellon SEI CERT Division with ExactData, LLC), synthetic", "release": report["release"],
        "reference": manifest["reference"]["doi"], "licence": manifest["reference"]["license"],
        "answer_key": "answers.tar.bz2 (insiders.csv plus the per-incident observables files r4.2-1, r4.2-2, r4.2-3)",
        "prepared_directory": str(processed), "preparation_seed": manifest["parameters"]["seed"], "users": report["users"], "insiders": report["insiders_in_population"],
        "windows_total": int(len(windows)), "destination_category_enrichment": "enabled" if categories else "disabled",
        "selected_files": [{"file": f"{k}.csv", "bytes": v["bytes"], "sha256": v.get("sha256")} for k, v in manifest["source_files"].items()]
                          + [{"file": f, "bytes": (processed / f).stat().st_size, "sha256": file_digest(processed / f)} for f in ("labels.csv", "splits.csv")],
        "event_counts": {k: v["rows_written"] for k, v in report["sources"].items()},
        "label_counts": {"answer_key_events_listed": report["labels"]["events_listed"], "labelled_malicious_events": report["labels"]["labelled_malicious"],
                         "ambiguous_events_excluded": report["labels"]["ambiguous_excluded_from_metrics"], "incidents": report["labels"]["incidents_in_key"],
                         "labels_csv_rows": int(len(labels))},
        "user_splits": splits.groupby("split").agg(users=("entity_id", "size"), insiders=("is_insider", "sum")).reset_index().to_dict("records"),
    }


def synthetic_dataset_info(processed: Path, windows: pd.DataFrame, splits: pd.DataFrame) -> dict:
    manifest = json.loads((processed / "manifest.json").read_text(encoding="utf-8"))
    return {
        "dataset": "project-generated synthetic supplement (ml/cert/synthetic.py), source = synthetic_test", "notice": SYNTHETIC_NOTICE,
        "generator_seed": manifest["seed"], "seed_mode": manifest["seed_mode"], "behaviour_profile": manifest["behaviour_profile"],
        "users": manifest["users"], "days": manifest["config"]["days"], "start_date": manifest["config"]["start"],
        "threat_start_fraction": manifest["config"].get("threat_start_fraction"), "windows_total": int(len(windows)),
        "event_counts": {"events_synthetic_test": manifest["event_count"]}, "label_counts": {"malicious_events": manifest["malicious_event_count"]},
        "scenarios": {k: v.get("events") for k, v in manifest["scenarios"].items()},
        "selected_files": [{"file": f, "bytes": (processed / f).stat().st_size, "sha256": file_digest(processed / f)}
                           for f in ("events_synthetic_test.csv.gz", "labels.csv", "eval_metadata.csv", "splits.csv", "manifest.json")],
        "user_splits": splits.groupby("split").agg(users=("entity_id", "size"), insiders=("is_insider", "sum")).reset_index().to_dict("records"),
    }


def run(args, log=print) -> dict:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    guard = out / "final_evaluation.json"
    if args.partition == "test":
        if not args.final:
            raise SystemExit("Evaluating the test partition needs --final (it may be evaluated once per output directory).")
        if guard.exists() and not args.force:
            raise SystemExit(f"The test partition was already evaluated into {out} ({guard.name}). Use a new --out, or --force only to reproduce.")
    t0 = time.time()
    protocol = Protocol(seed=args.seed)
    results = {"tracks": {}}
    tables: dict[str, pd.DataFrame] = {}

    if not args.skip_cert:
        processed = Path(args.cert_processed)
        log("CERT: verifying that the event files hold only CERT records ...")
        source_check = verify_cert_sources(processed)
        cache = processed / "windows_labelled.pkl"
        if cache.exists():
            windows = pd.read_pickle(cache)
        else:
            windows = attach_window_labels(build_cert_windows(processed, log=log), processed, exclude_incident_gaps=True)
            windows.to_pickle(cache)
        if args.no_categories:
            windows = windows.assign(n_cat_job=0.0, n_cat_exfil=0.0)
        splits = pd.read_csv(processed / "splits.csv")
        attributes = pd.read_csv(processed / "entity_attributes.csv") if (processed / "entity_attributes.csv").exists() else None
        info = {**cert_dataset_info(processed, windows, splits, not args.no_categories), "source_check": source_check}
        track, extra = run_track("cert", windows, splits, attributes, incidents_table(processed), replace(protocol, train_end_fraction=0.45, validation_end_fraction=0.52),
                                 partition=args.partition, use_time=True, dataset_info=info, log=log)
        results["tracks"]["cert"] = track
        tables.update(flatten(track, extra))

    if not args.skip_synthetic:
        processed = Path(args.synthetic_processed)
        if not (processed / "manifest.json").exists():
            log(f"synthetic: generating a fresh set (seed {args.synthetic_seed}) into {processed} ...")
            profile = Path(args.cert_processed) / "cert_profile.json"
            synthetic.generate(processed, synthetic.SyntheticConfig(seed=args.synthetic_seed, n_users=600, days=150, threat_start_fraction=0.30),
                               profile_path=profile if profile.exists() else None)
        cache = processed / "windows_labelled.pkl"
        windows = pd.read_pickle(cache) if cache.exists() else load_synthetic_windows(processed)
        if not cache.exists():
            windows.to_pickle(cache)
        splits = pd.read_csv(processed / "splits.csv")
        splits = splits.assign(is_insider=splits["is_insider"].astype(bool))
        track, extra = run_track("synthetic", windows, splits, None, incidents_from(processed), replace(protocol, train_end_fraction=0.45, validation_end_fraction=0.65),
                                 partition=args.partition, use_time=True, dataset_info=synthetic_dataset_info(processed, windows, splits), log=log)
        results["tracks"]["synthetic"] = track
        tables.update(flatten(track, extra))

    if not args.skip_unit:
        world = scenarios.build_unit_world(seed=args.unit_seed)
        info = {"dataset": "manually created unit-test scenarios (ml/detect/scenarios.py)", "generator_seed": world.seed, "users": scenarios.N_USERS,
                "days": scenarios.DAYS, "windows_total": int(len(world.windows)), "event_counts": {"events": int(len(world.frame))},
                "label_counts": {"malicious_events": int((world.windows["n_malicious_events"]).sum())},
                "scenarios": {f"{who} ({kind})": outcome for who, (outcome, kind) in world.expectations.items()},
                "note": "36 ordinary users (24 train, 12 validation) and 4 scenario users held out as the test partition"}
        track, extra = run_track("unit_scenarios", world.windows, world.splits.assign(is_insider=False), None, world.incidents, replace(protocol, bootstrap_resamples=100),
                                 partition=args.partition, use_time=False, dataset_info=info, log=log)
        results["tracks"]["unit_scenarios"] = track
        tables.update(flatten(track, extra))

    command = getattr(args, "command", None) or "python -m ml.detect.run_evaluation --out " + str(args.out)
    results["manifest"] = {
        "generated_at": pd.Timestamp.utcnow().isoformat(), "seconds": round(time.time() - t0), "partition": args.partition, "command": command,
        "protocol": protocol.as_dict(), "software": software_versions(), "git": git_state(ROOT), "feature_count": len(FEATURE_COLUMNS),
        "hybrid_config_sha256": config_hash(hybrid_config()), "frozen_config_check": frozen_config_check(Path(args.cert_processed).parent / "reports"),
        "notes": [
            "The CERT test users were already evaluated once in the earlier benchmark (whole timeline, user-disjoint split). This protocol re-uses the same "
            "frozen configuration on a later time slice of those users, so it is not a fresh, never-seen test set. No rule, feature or weight was changed.",
            "The synthetic track uses a new generator seed, so its test users and incidents were never seen during development.",
            "Fitting (peer baseline, destination statistics, models, baseline-rule thresholds) used the train partition; thresholds used benign "
            "validation windows only; the evaluated partition's labels were blanked before fitting.",
            "Time cutoffs are fractions of each dataset's window date range (CERT 45 % / 52 %, synthetic 45 % / 65 %); incidents that straddle a cutoff "
            "are listed and excluded rather than half-used. The synthetic generator was run with threat_start_fraction 0.30 so attacks occur across "
            "most of the timeline (its default of 0.55 would leave no attacks in a time-ordered training period).",
        ] + (["Development run on the validation partition: not a held-out result."] if args.partition != "test" else []),
    }
    results["limitations"] = LIMITATIONS
    (out / "results.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    (out / "manifest.json").write_text(json.dumps(results["manifest"], indent=2, default=str), encoding="utf-8")
    for name, frame in tables.items():
        frame.to_csv(out / name, index=False)
    (out / "report.md").write_text(render(results), encoding="utf-8")
    if args.partition == "test":
        guard.write_text(json.dumps({"evaluated_at": results["manifest"]["generated_at"], "hybrid_config_sha256": results["manifest"]["hybrid_config_sha256"],
                                     "command": command}), encoding="utf-8")
    log(f"wrote {out / 'report.md'} ({results['manifest']['seconds']} s)")
    return results


def incidents_from(processed: Path) -> pd.DataFrame:
    from ml.detect.dataset import incidents_table

    return incidents_table(processed)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cert-processed", default="data/processed/cert_r4.2")
    p.add_argument("--synthetic-processed", default="data/processed/synthetic_protocol_v2")
    p.add_argument("--synthetic-seed", type=int, default=2026)
    p.add_argument("--unit-seed", type=int, default=5)
    p.add_argument("--out", default="reports/evaluation")
    p.add_argument("--partition", choices=["validation", "test"], default="validation")
    p.add_argument("--final", action="store_true", help="required to evaluate the test partition (once per --out)")
    p.add_argument("--force", action="store_true")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-categories", action="store_true", help="ablation: disable the destination-category enrichment")
    p.add_argument("--skip-cert", action="store_true")
    p.add_argument("--skip-synthetic", action="store_true")
    p.add_argument("--skip-unit", action="store_true")
    argv = list(sys.argv[1:] if argv is None else argv)
    args = p.parse_args(argv)
    args.command = "python -m ml.detect.run_evaluation " + " ".join(argv)
    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
