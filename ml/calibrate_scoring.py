"""Choose the risk-band thresholds on validation runs and report what that costs.

    python -m ml.calibrate_scoring                 # about 10-15 minutes; writes reports/calibration/ and backend/operating_point.json

What it does
------------
1. Runs each of the project's eight seeded scenarios (two benign, six malicious) through the real ingestion and detection
   pipeline, on a temporary database, for a set of **validation seeds** and a disjoint set of **test seeds**.
2. For each run records the heuristic risk score (and the independent-stage count and anomaly score) reached by the target
   employee, and by any employee for the benign runs.
3. Chooses each band's threshold from the **validation** runs only: the lowest threshold whose false-flag rate on the
   benign validation runs stays inside the band's budget (that maximises recall subject to the budget).
4. Reports the trade-off between missed detections and false flags on validation and, separately, on the untouched test
   runs. The test runs never influence a threshold.

What it cannot tell you
-----------------------
The labels are the generator's own (a scenario is malicious by construction), the benign class is two scenarios, and the test
seeds come from the same generators as the validation seeds, so the test figures are optimistic about unseen behaviour. The
risk score is still a heuristic and the thresholds are an operating point on synthetic runs, not a calibrated probability.
Nothing here validates the system on real employees or real incidents.
"""
import argparse
import csv
import json
import os
import platform
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "reports" / "calibration"
OPERATING_POINT = ROOT / "backend" / "operating_point.json"

# The independent attack stages a band requires (the same gate the engine applies) and the share of benign runs that
# may reach that band. These budgets are policy choices (how many false flags an analyst can absorb), not measurements.
BAND_GATES = {"suspicious": 0, "high_risk": 2, "critical": 3}
BAND_LABELS = {"suspicious": "Watch", "high_risk": "Elevated", "critical": "Alert"}
FALSE_FLAG_BUDGET = {"suspicious": 0.25, "high_risk": 0.05, "critical": 0.0}
ML_FALSE_AGREE_BUDGET = 0.05
GRID = range(0, 101)
BENIGN = ("benign_activity", "benign_bulk_transfer")
MALICIOUS = ("gradual_collection_staging", "bulk_export", "suspicious_external_transfer", "removable_media",
             "correlated_low_signals", "compromised_account_campaign")
VALIDATION_SEED_BASE, TEST_SEED_BASE = 1000, 2000


@dataclass
class RunRecord:
    scenario: str
    label: int                                   # 1 malicious, 0 benign (by the scenario's definition)
    split: str                                   # validation | test
    seed: int
    target_best: dict[int, float] = field(default_factory=dict)   # gate -> best score by the target with >= gate stages (-1: none)
    any_best: dict[int, float] = field(default_factory=dict)      # the same over every employee in the run
    target_ml_peak: float = 0.0
    any_ml_peak: float = 0.0
    series: list[list] = field(default_factory=list)              # target: [event index, score, stages, anomaly]


# ----------------------------------------------------------------------------------------------- pure calculations
def flagged(record: RunRecord, band: str, threshold: int, *, who: str) -> bool:
    best = (record.target_best if who == "target" else record.any_best).get(BAND_GATES[band], -1)
    return best >= threshold


def rates(records: list[RunRecord], band: str, threshold: int) -> dict:
    mal = [r for r in records if r.label == 1]
    ben = [r for r in records if r.label == 0]
    tp = sum(flagged(r, band, threshold, who="target") for r in mal)
    fp = sum(flagged(r, band, threshold, who="any") for r in ben)
    return {"threshold": threshold, "tp": tp, "fn": len(mal) - tp, "fp": fp, "tn": len(ben) - fp,
            "recall": tp / len(mal) if mal else None, "miss_rate": (len(mal) - tp) / len(mal) if mal else None,
            "false_flag_rate": fp / len(ben) if ben else None, "precision": tp / (tp + fp) if (tp + fp) else None}


def select_threshold(validation: list[RunRecord], band: str) -> dict:
    """Lowest threshold whose validation false-flag rate is inside the band's budget. Recall never rises with the threshold,
    so this is the point that misses the fewest validation detections without exceeding the budget."""
    budget = FALSE_FLAG_BUDGET[band]
    feasible = [t for t in GRID if (rates(validation, band, t)["false_flag_rate"] or 0.0) <= budget]
    if not feasible:
        return {"threshold": max(GRID), "note": "no threshold met the false-flag budget; the highest was used"}
    chosen = rates(validation, band, min(feasible))
    return {"threshold": min(feasible), "validation_recall": chosen["recall"], "validation_false_flag_rate": chosen["false_flag_rate"]}


def select_thresholds(validation: list[RunRecord]) -> dict[str, int]:
    chosen = {band: select_threshold(validation, band)["threshold"] for band in BAND_GATES}
    chosen["high_risk"] = max(chosen["high_risk"], chosen["suspicious"])      # bands must be ordered
    chosen["critical"] = max(chosen["critical"], chosen["high_risk"])
    return chosen


def select_ml_threshold(validation: list[RunRecord]) -> float:
    """Lowest anomaly score at which the model counts as agreeing, keeping benign validation runs' false agreement in budget."""
    benign = [r for r in validation if r.label == 0]
    for step in range(0, 21):
        theta = step / 20
        if benign and sum(r.any_ml_peak >= theta for r in benign) / len(benign) <= ML_FALSE_AGREE_BUDGET:
            return theta
    return 1.0


def per_scenario(records: list[RunRecord], thresholds: dict[str, int]) -> dict:
    out = {}
    for scenario in sorted({r.scenario for r in records}):
        group = [r for r in records if r.scenario == scenario]
        entry = {"runs": len(group), "label": "malicious" if group[0].label else "benign"}
        for band, t in thresholds.items():
            n = sum(flagged(r, band, t, who="target" if group[0].label else "any") for r in group)
            entry[f"{BAND_LABELS[band].lower()}_flagged"] = n
            entry[f"{BAND_LABELS[band].lower()}_rate"] = round(n / len(group), 3)
        entry["peak_score_median"] = _median([r.target_best.get(0, -1) for r in group])
        out[scenario] = entry
    return out


def early_warning(records: list[RunRecord], threshold: int) -> dict:
    """Among malicious runs that reached the Alert band: how many did so before the target's last event in the run."""
    reached, early = 0, 0
    for r in (x for x in records if x.label == 1):
        crossing = next((i for i, (_idx, score, stages, _ml) in enumerate(r.series)
                         if score >= threshold and stages >= BAND_GATES["critical"]), None)
        if crossing is None:
            continue
        reached += 1
        early += crossing < len(r.series) - 1
    return {"malicious_runs_reaching_alert": reached, "before_the_final_event": early,
            "note": "'final event' is the target's last scored event in the run; for most scenarios that is the closing logout"}


def tradeoff(records: list[RunRecord], band: str, step: int = 5) -> list[dict]:
    return [rates(records, band, t) for t in range(0, 101, step)]


def evaluate(records: list[RunRecord], thresholds: dict[str, int]) -> dict:
    return {"runs": len(records), "malicious_runs": sum(r.label for r in records),
            "benign_runs": sum(1 - r.label for r in records),
            "bands": {BAND_LABELS[b]: rates(records, b, t) for b, t in thresholds.items()},
            "per_scenario": per_scenario(records, thresholds), "early_warning": early_warning(records, thresholds["critical"])}


def _median(values: list[float]) -> float | None:
    values = sorted(values)
    return None if not values else values[len(values) // 2]


# --------------------------------------------------------------------------------------------------- running scenarios
def _pin_clock() -> timedelta:
    """Run at 10:30 local time on a weekday so results do not depend on when the script is run. Must precede importing backend.main."""
    from zoneinfo import ZoneInfo

    import backend.database as database
    from backend.config import get_settings

    tz = ZoneInfo(get_settings().display_timezone)
    local = datetime.now(timezone.utc).astimezone(tz)
    target = local.replace(hour=10, minute=30, second=0, microsecond=0)
    while target.weekday() >= 5:
        target += timedelta(days=1)
    shift = target - local
    real = database.utcnow
    database.utcnow = lambda: real() + shift
    return shift


def collect(seeds_per_split: int, log=print) -> list[RunRecord]:
    from fastapi.testclient import TestClient
    from sqlalchemy import select

    from backend.database import SessionLocal
    from backend.main import app
    from backend.models import RiskAssessment, SecurityEvent
    from data.demo_accounts import demo_password

    records: list[RunRecord] = []
    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"employee_id": "SEC-9011", "password": demo_password("SEC-9011")})
        login.raise_for_status()
        admin = {"Authorization": f"Bearer {login.json()['access_token']}"}
        plan = [(split, base + i) for split, base in (("validation", VALIDATION_SEED_BASE), ("test", TEST_SEED_BASE))
                for i in range(seeds_per_split)]
        total, done, started = len(plan) * (len(BENIGN) + len(MALICIOUS)), 0, time.time()
        for split, seed in plan:
            for scenario in (*BENIGN, *MALICIOUS):
                response = client.post("/api/simulation/runs", headers=admin, json={"scenario": scenario, "seed": seed, "pace": "instant"})
                if response.status_code != 202:
                    raise RuntimeError(f"{scenario} seed {seed}: {response.status_code} {response.text[:200]}")
                run_id = response.json()["id"]
                while True:
                    run = client.get(f"/api/simulation/runs/{run_id}", headers=admin).json()
                    if run["status"] in ("completed", "failed", "cancelled"):
                        break
                    time.sleep(0.05)
                if run["status"] != "completed":
                    raise RuntimeError(f"{scenario} seed {seed} ended {run['status']}: {run.get('error')}")
                target_id = run["target"]["id"]
                with SessionLocal() as db:
                    event_ids = [e for (e,) in db.execute(select(SecurityEvent.id).where(SecurityEvent.simulation_run_id == run_id))]
                    rows = db.execute(select(RiskAssessment.employee_id, RiskAssessment.event_id, RiskAssessment.score,
                                             RiskAssessment.components, RiskAssessment.ml_score)
                                      .where(RiskAssessment.event_id.in_(event_ids or [0]))
                                      .order_by(RiskAssessment.event_id, RiskAssessment.id)).all()
                records.append(_record(scenario, split, seed, target_id, rows))
                client.post("/api/simulation/reset", headers=admin)
                done += 1
                if done % 10 == 0 or done == total:
                    log(f"  {done}/{total} runs ({time.time() - started:.0f}s)")
    return records


def _record(scenario: str, split: str, seed: int, target_id: int, rows) -> RunRecord:
    rec = RunRecord(scenario, 1 if scenario in MALICIOUS else 0, split, seed)
    best_t = {g: -1.0 for g in BAND_GATES.values()}
    best_a = dict(best_t)
    for index, (emp_id, _event_id, score, components, ml) in enumerate(rows):
        stages = int((components or {}).get("independent_stages", 0))
        for g in best_t:
            if stages >= g:
                best_a[g] = max(best_a[g], score)
                if emp_id == target_id:
                    best_t[g] = max(best_t[g], score)
        rec.any_ml_peak = max(rec.any_ml_peak, ml or 0.0)
        if emp_id == target_id:
            rec.target_ml_peak = max(rec.target_ml_peak, ml or 0.0)
            rec.series.append([index, score, stages, round(ml or 0.0, 3)])
    rec.target_best, rec.any_best = best_t, best_a
    return rec


# ------------------------------------------------------------------------------------------------------------ report
def build_result(records: list[RunRecord], seeds_per_split: int) -> dict:
    validation = [r for r in records if r.split == "validation"]
    test = [r for r in records if r.split == "test"]
    thresholds = select_thresholds(validation)
    theta = select_ml_threshold(validation)
    defaults = {"suspicious": 25, "high_risk": 50, "critical": 80}
    import numpy
    import sklearn
    result = {
        "status": "calibrated on synthetic validation runs",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "thresholds": thresholds, "ml_corroboration_threshold": theta,
        "selected_on": {"split": "validation", "seeds": [VALIDATION_SEED_BASE, VALIDATION_SEED_BASE + seeds_per_split - 1],
                        "runs": len(validation), "scenarios": {"benign": list(BENIGN), "malicious": list(MALICIOUS)}},
        "targets": {"false_flag_budget_on_benign_validation_runs": {BAND_LABELS[b]: v for b, v in FALSE_FLAG_BUDGET.items()},
                    "ml_false_agreement_budget": ML_FALSE_AGREE_BUDGET,
                    "rule": "lowest threshold whose false-flag rate on benign validation runs is within the band's budget",
                    "stage_gates": {BAND_LABELS[b]: g for b, g in BAND_GATES.items()},
                    "note": "the budgets are policy assumptions about analyst capacity, not measurements"},
        "selection_detail": {BAND_LABELS[b]: select_threshold(validation, b) for b in BAND_GATES},
        "validation": evaluate(validation, thresholds),
        "test": {"seeds": [TEST_SEED_BASE, TEST_SEED_BASE + seeds_per_split - 1], **evaluate(test, thresholds)},
        "uncalibrated_defaults_on_test": {"thresholds": defaults, **evaluate(test, defaults)},
        "tradeoff": {"alert_band_validation": tradeoff(validation, "critical"), "alert_band_test": tradeoff(test, "critical"),
                     "elevated_band_validation": tradeoff(validation, "high_risk"), "watch_band_validation": tradeoff(validation, "suspicious")},
        "software": {"python": platform.python_version(), "numpy": numpy.__version__, "scikit_learn": sklearn.__version__},
        "limitations": [
            "Run labels are the generator's own: a scenario is malicious by construction. There are two benign scenarios.",
            "Test seeds are drawn from the same generators as the validation seeds, so test figures are optimistic about unseen behaviour.",
            "The risk score is a heuristic. These thresholds are an operating point on synthetic runs, not a calibrated probability.",
            "Not validated on real employees, real incidents or a live banking environment.",
        ],
    }
    result["findings"] = findings(result)
    return result


def findings(result: dict) -> list[str]:
    """Plain-language observations a reader needs to interpret the thresholds; computed from the numbers, not written by hand."""
    notes = []
    for band, label in BAND_LABELS.items():
        own = result["selection_detail"][label]["threshold"]
        if own < result["thresholds"][band]:
            notes.append(f"{label}: the budget alone allowed a threshold of {own}; it was raised to {result['thresholds'][band]} so the bands "
                         "stay ordered. For this band the independent-stage requirement, not the score threshold, is what separates "
                         "benign runs from malicious ones.")
    for label, budget in ((BAND_LABELS[b], FALSE_FLAG_BUDGET[b]) for b in BAND_GATES):
        validation_rate = result["validation"]["bands"][label]["false_flag_rate"]
        test_rate = result["test"]["bands"][label]["false_flag_rate"]
        if test_rate is not None and test_rate > budget:
            notes.append(f"{label}: the false-flag rate on held-out test runs ({test_rate:.1%}) exceeds the budget ({budget:.0%}) that "
                         f"held on validation ({validation_rate:.1%}); a budget met on validation does not guarantee it on new seeds.")
    for label, r in result["test"]["bands"].items():
        notes.append(f"{label}: {r['tp']} of {r['tp'] + r['fn']} malicious test runs detected "
                     f"({r['recall']:.0%}); {r['fn']} missed; {r['fp']} of {r['fp'] + r['tn']} benign runs flagged.")
    return notes


def markdown(result: dict) -> str:
    th, v, t = result["thresholds"], result["validation"], result["test"]
    lines = ["# Risk-band calibration", "",
             f"Generated {result['generated_at']}. Software: {result['software']}.", "",
             "**Synthetic runs only.** " + " ".join(result["limitations"]), "",
             "## Selected operating point", "",
             "| Band | Threshold (risk score) | Independent stages needed | False-flag budget (benign validation runs) |", "|---|---|---|---|"]
    for band in BAND_GATES:
        label = BAND_LABELS[band]
        lines.append(f"| {label} | {th[band]} | {BAND_GATES[band] or 'none'} | {FALSE_FLAG_BUDGET[band]:.0%} |")
    lines += ["", f"Anomaly-model corroboration threshold: {result['ml_corroboration_threshold']:.2f}.", "",
              f"Rule: {result['targets']['rule']}. Chosen on {v['runs']} validation runs "
              f"({v['malicious_runs']} malicious, {v['benign_runs']} benign), seeds {result['selected_on']['seeds'][0]}-{result['selected_on']['seeds'][1]}.", ""]
    for title, ev in (("Validation (used to choose the thresholds)", v), ("Held-out test (never used to choose anything)", t)):
        lines += [f"## {title}", "", f"{ev['runs']} runs: {ev['malicious_runs']} malicious, {ev['benign_runs']} benign.", "",
                  "| Band | Threshold | Detected | Missed | False flags | Correct benign | Miss rate | False-flag rate |", "|---|---|---|---|---|---|---|---|"]
        for label, r in ev["bands"].items():
            lines.append(f"| {label} | {r['threshold']} | {r['tp']} | {r['fn']} | {r['fp']} | {r['tn']} | "
                         f"{r['miss_rate']:.1%} | {r['false_flag_rate']:.1%} |")
        lines += ["", "| Scenario | Kind | Runs | Watch | Elevated | Alert |", "|---|---|---|---|---|---|"]
        for name, s in ev["per_scenario"].items():
            lines.append(f"| {name} | {s['label']} | {s['runs']} | {s['watch_flagged']} | {s['elevated_flagged']} | {s['alert_flagged']} |")
        ew = ev["early_warning"]
        lines += ["", f"Early warning: {ew['before_the_final_event']} of {ew['malicious_runs_reaching_alert']} malicious runs that reached "
                      "the Alert band did so before the target's final scored event.", ""]
    lines += ["## Trade-off for the Alert band (validation)", "",
              "| Threshold | Missed detections | False flags on benign runs |", "|---|---|---|"]
    for r in result["tradeoff"]["alert_band_validation"]:
        lines.append(f"| {r['threshold']} | {r['miss_rate']:.1%} ({r['fn']}) | {r['false_flag_rate']:.1%} ({r['fp']}) |")
    lines += ["", "Raising a threshold removes false flags and adds missed detections; the table shows where this project's synthetic runs "
                  "sit on that curve. The same thresholds applied to the test runs:", "",
              "| Threshold | Missed detections | False flags on benign runs |", "|---|---|---|"]
    for r in result["tradeoff"]["alert_band_test"]:
        lines.append(f"| {r['threshold']} | {r['miss_rate']:.1%} ({r['fn']}) | {r['false_flag_rate']:.1%} ({r['fp']}) |")
    lines += ["", "## Findings", ""] + [f"* {n}" for n in result["findings"]]
    d = result["uncalibrated_defaults_on_test"]
    lines += ["", f"For comparison, the earlier hand-picked thresholds ({d['thresholds']}) on the same test runs: "
              + "; ".join(f"{k}: {r['tp']}/{r['tp'] + r['fn']} detected, {r['fp']}/{r['fp'] + r['tn']} false flags" for k, r in d["bands"].items()) + "."]
    return "\n".join(lines) + "\n"


def write_outputs(result: dict, records: list[RunRecord], *, operating_point: Path | None, out_dir: Path = OUT_DIR) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scoring_calibration.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (out_dir / "scoring_calibration.md").write_text(markdown(result), encoding="utf-8")
    with open(out_dir / "runs.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["split", "seed", "scenario", "label", "best_score_any_stage", "best_score_2_stages", "best_score_3_stages",
                    "target_anomaly_peak", "any_best_score", "any_anomaly_peak"])
        for r in records:
            w.writerow([r.split, r.seed, r.scenario, r.label, r.target_best.get(0), r.target_best.get(2), r.target_best.get(3),
                        round(r.target_ml_peak, 3), r.any_best.get(0), round(r.any_ml_peak, 3)])
    if operating_point is not None:
        keep = ("status", "generated_at", "thresholds", "ml_corroboration_threshold", "selected_on", "targets", "validation",
                "test", "software", "limitations", "findings")
        point = {k: result[k] for k in keep}
        point["validation"] = {k: v for k, v in point["validation"].items() if k in ("runs", "malicious_runs", "benign_runs", "bands")}
        point["test"] = {k: v for k, v in point["test"].items() if k in ("seeds", "runs", "malicious_runs", "benign_runs", "bands")}
        point["tradeoff"] = {"alert_band_validation": result["tradeoff"]["alert_band_validation"]}
        operating_point.write_text(json.dumps(point, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ml.calibrate_scoring", description=__doc__.split("\n\n")[0])
    parser.add_argument("--seeds", type=int, default=12, help="seeds per split (validation and test each); default 12, the number behind backend/operating_point.json")
    parser.add_argument("--no-write-operating-point", action="store_true", help="write only the reports, not backend/operating_point.json")
    parser.add_argument("--out", type=Path, default=OUT_DIR)
    args = parser.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="itd_calibration_"))
    os.environ.update({
        "DATABASE_URL": f"sqlite:///{(work / 'calibration.db').as_posix()}", "AUTO_SEED": "true", "APP_ENV": "development",
        "SECRET_KEY": "calibration-run-secret-not-used-elsewhere", "ML_MODEL_PATH": str(work / "model.joblib"),
        "LOCAL_SECRET_FILE": str(work / "local_secret"), "DEMO_CREDENTIALS_FILE": str(work / "demo_credentials.json"),
        "OPERATING_POINT_PATH": str(work / "none.json"), "LAB_MODE": "true",       # calibration drives the offline scenario lab
        "RATE_LIMIT_SENSITIVE_PER_MINUTE": "1000000", "RATE_LIMIT_HEAVY_PER_MINUTE": "1000000",
        "RATE_LIMIT_EMPLOYEE_PER_MINUTE": "1000000", "ARGON2_TIME_COST": "1", "ARGON2_MEMORY_KIB": "8", "ARGON2_PARALLELISM": "1",
    })
    os.environ.pop("DEMO_PASSWORDS_JSON", None)
    sys.path.insert(0, str(ROOT))
    shift = _pin_clock()
    print(f"Calibration on a temporary database ({work}); clock pinned to a weekday 10:30 local ({shift} shift).")
    records = collect(args.seeds)
    result = build_result(records, args.seeds)
    write_outputs(result, records, operating_point=None if args.no_write_operating_point else OPERATING_POINT, out_dir=args.out)
    print(json.dumps({"thresholds": result["thresholds"], "ml_corroboration_threshold": result["ml_corroboration_threshold"],
                      "test_alert_band": result["test"]["bands"]["Alert"]}, indent=2))
    print(f"Wrote {args.out}" + ("" if args.no_write_operating_point else f" and {OPERATING_POINT}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
